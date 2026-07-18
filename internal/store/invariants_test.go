package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
)

func TestSharedLocalNameNamespaceIsAtomic(t *testing.T) {
	s := newStore(t)
	start := make(chan struct{})
	errCh := make(chan error, 2)
	go func() {
		<-start
		_, _, err := s.CreateAgent("same-name", "", false)
		errCh <- err
	}()
	go func() {
		<-start
		_, _, _, err := s.CreatePersonWithAgent("same-name", "owner@example.com", "laptop", 0)
		errCh <- err
	}()
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		if err := <-errCh; err == nil {
			winners++
		} else if !errors.Is(err, ErrNameTaken) && !errors.Is(err, ErrHandleTaken) {
			t.Fatalf("unexpected namespace error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("namespace winners=%d, want exactly one", winners)
	}
	var reservations int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM local_names WHERE name='same-name'`).Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if reservations != 1 {
		t.Fatalf("local_names reservations=%d, want 1", reservations)
	}
	var orphans int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agents a WHERE a.person_id<>''
		AND NOT EXISTS (SELECT 1 FROM persons p WHERE p.id=a.person_id)`).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Fatalf("orphan person-owned agents=%d", orphans)
	}
}

func TestStorageReferenceInspectionPropagatesDatabaseErrors(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("storage-inspection", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DROP TABLE spaces`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AgentUsesStorageBlob(a.ID, strings.Repeat("a", 64)); err == nil {
		t.Fatal("storage reference query failure was reported as an uncharged blob")
	}
	if _, err := s.StorageUsed(a.ID); err == nil {
		t.Fatal("storage usage query failure was reported as zero bytes")
	}
}

func TestLocalNameMigrationBackfillsAndRejectsLegacyCollision(t *testing.T) {
	openV10 := func(t *testing.T, path string) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 10; i++ {
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(migrations[i]); err != nil {
				t.Fatalf("migration %d: %v", i+1, err)
			}
			if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, i+1)); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		return db
	}

	db := openV10(t, filepath.Join(t.TempDir(), "clean.db"))
	if _, err := db.Exec(`INSERT INTO agents(id,name,email,key_hash,created_at)
		VALUES('a1','legacy-agent','legacy-agent@local','x',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO persons(id,handle,email,created_at)
		VALUES('p1','legacy-person','owner@example.com',1)`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	var names int
	if err := db.QueryRow(`SELECT COUNT(*) FROM local_names`).Scan(&names); err != nil || names != 2 {
		t.Fatalf("backfilled names=%d err=%v", names, err)
	}
	db.Close()

	colliding := openV10(t, filepath.Join(t.TempDir(), "collision.db"))
	defer colliding.Close()
	if _, err := colliding.Exec(`INSERT INTO agents(id,name,email,key_hash,created_at)
		VALUES('a1','collision','collision@local','x',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := colliding.Exec(`INSERT INTO persons(id,handle,email,created_at)
		VALUES('p1','collision','owner@example.com',1)`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(colliding); err == nil {
		t.Fatal("legacy cross-table collision migrated without operator intervention")
	}
}

func TestConcurrentVerifiedOwnerCapIsNotOversubscribed(t *testing.T) {
	s := newStore(t)
	const attempts = 12
	tokens := make([]string, 0, attempts)
	for i := 0; i < attempts; i++ {
		a, _, err := s.CreateAgentLimited(fmt.Sprintf("capped-%02d", i), "victim@example.com", false, 1)
		if err != nil {
			t.Fatalf("pending nomination %d was blocked: %v", i, err)
		}
		token, err := s.CreateOwnerVerifyToken(a.ID, a.OwnerEmail)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	start := make(chan struct{})
	type result struct {
		token string
		err   error
	}
	results := make(chan result, attempts)
	var wg sync.WaitGroup
	for _, token := range tokens {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			<-start
			_, err := s.VerifyOwnerTokenLimited(token, 1)
			results <- result{token: token, err: err}
		}(token)
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err == nil {
			winners++
		} else if errors.Is(result.err, ErrOwnerAgentLimit) {
			if _, err := s.PeekVerifyToken(result.token); err != nil {
				t.Fatalf("cap failure consumed retryable token: %v", err)
			}
		} else {
			t.Fatalf("unexpected cap error: %v", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("owner-cap winners=%d, want 1", winners)
	}
	if n, err := s.CountAgentsByOwner("victim@example.com"); err != nil || n != 1 {
		t.Fatalf("owner count=%d err=%v", n, err)
	}
}

func TestStaleUnverifiedOwnerNominationsAreReaped(t *testing.T) {
	s := newStore(t)
	flat, _, err := s.CreateAgent("stale-flat-owner", "victim@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	person, fleet, _, err := s.CreatePersonWithAgent("stale-fleet", "victim@example.com", "laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	ownerless, _, err := s.CreateAgent("old-ownerless", "", false)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _, err := s.CreateAgent("fresh-nomination", "victim@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, err := s.CreateAgent("verified-nomination", "verified@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateOwnerVerifyToken(verified.ID, verified.OwnerEmail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyOwnerTokenLimited(token, 1); err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "stale active link")
	if _, err := s.AddFile(flat.ID, sha, "stale.bin", "application/octet-stream", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	link, err := s.CreateLink(flat.ID, sha, "stale.bin", "application/octet-stream", size, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agents SET owner_pending_at=1 WHERE id IN (?,?)`, flat.ID, fleet.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE persons SET created_at=1 WHERE id=?`, person.ID); err != nil {
		t.Fatal(err)
	}
	deletions, err := s.SweepStaleUnverifiedOwnerAgents(48 * 3600)
	if err != nil {
		t.Fatal(err)
	}
	deleted := map[string]StaleAgentDeletion{}
	for _, deletion := range deletions {
		deleted[deletion.Agent.ID] = deletion
	}
	if len(deleted) != 2 || deleted[flat.ID].Agent.ID == "" || deleted[fleet.ID].Agent.ID == "" {
		t.Fatalf("stale deletions=%+v, want flat and fleet", deletions)
	}
	if len(deleted[flat.ID].ActiveTokens) != 1 || deleted[flat.ID].ActiveTokens[0] != link.Token {
		t.Fatalf("stale active tokens=%v", deleted[flat.ID].ActiveTokens)
	}
	for _, survivor := range []string{ownerless.ID, fresh.ID, verified.ID} {
		if _, err := s.AgentByID(survivor); err != nil {
			t.Fatalf("eligible survivor %s was reaped: %v", survivor, err)
		}
	}
	if released, err := s.SweepStalePendingPersons(48 * 3600); err != nil || released != 1 {
		t.Fatalf("empty stale person release=%d err=%v", released, err)
	}
}

func TestDeleteFileConcurrentCallersDoNotPanicOrPartiallyReturn(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("delete-race", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "shared delete bytes")
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		if _, err := s.AddFile(a.ID, sha, name, "application/octet-stream", size, "upload", true, 0); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan struct {
		files int
		err   error
	}, 16)
	for i := 0; i < 16; i++ {
		go func() {
			<-start
			files, err := s.DeleteFile(a.ID, sha)
			results <- struct {
				files int
				err   error
			}{len(files), err}
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 16; i++ {
		r := <-results
		if r.err == nil {
			winners++
			if r.files != 3 {
				t.Fatalf("winner returned %d rows, want all 3", r.files)
			}
		} else if !errors.Is(r.err, ErrNotFound) {
			t.Fatalf("delete error: %v", r.err)
		}
	}
	if winners != 1 {
		t.Fatalf("delete winners=%d, want 1", winners)
	}
}

func TestActiveLinkAndSpaceOwnerRemainCharged(t *testing.T) {
	s := newStore(t)
	owner, _, _ := s.CreateAgent("space-charge-owner", "", false)
	member, _, _ := s.CreateAgent("space-charge-member", "", false)
	sha, size := put(t, s, "durable charge")
	if _, err := s.AddFile(member.ID, sha, "offer.bin", "application/octet-stream", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	link, err := s.CreateLink(member.ID, sha, "offer.bin", "application/octet-stream", size, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFile(member.ID, sha); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.StorageUsed(member.ID); used != size {
		t.Fatalf("active link charge=%d, want %d", used, size)
	}
	if _, err := s.RevokeLink(link.Token); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.StorageUsed(member.ID); used != 0 {
		t.Fatalf("revoked link charge=%d, want 0", used)
	}

	sp, err := s.CreateSpace(owner.ID, "owned")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSpaceEvent(sp.ID, member.Email, "file", "", sha, "offer.bin", "application/octet-stream", size); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.StorageUsed(owner.ID); used != size {
		t.Fatalf("space owner charge=%d, want %d", used, size)
	}
	if used, _ := s.StorageUsed(member.ID); used != 0 {
		t.Fatalf("space member charge=%d, want 0", used)
	}
	if _, _, err := s.DeleteAgent(member.ID); err != nil {
		t.Fatal(err)
	}
	replacement, _, err := s.CreateAgent("space-charge-member", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := s.StorageUsed(replacement.ID); used != 0 {
		t.Fatalf("re-registered actor inherited old charge=%d", used)
	}
	if used, _ := s.StorageUsed(owner.ID); used != size {
		t.Fatalf("owner lost charge after member deletion: %d", used)
	}
}

func TestTopStorageConsumersMatchesDistinctLogicalCharge(t *testing.T) {
	s := newStore(t)
	owner, _, _ := s.CreateAgent("storage-report-owner", "", false)
	member, _, _ := s.CreateAgent("storage-report-member", "", false)

	fileSHA, fileSize := put(t, s, "folder bytes")
	for _, name := range []string{"first.bin", "duplicate-name.bin"} {
		if _, err := s.AddFile(owner.ID, fileSHA, name, "application/octet-stream", fileSize, "upload", true, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateLink(owner.ID, fileSHA, "first.bin", "application/octet-stream", fileSize, false, time.Hour); err != nil {
		t.Fatal(err)
	}

	linkSHA, linkSize := put(t, s, "link-only bytes are different")
	if _, err := s.AddFile(owner.ID, linkSHA, "link-only.bin", "application/octet-stream", linkSize, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLink(owner.ID, linkSHA, "link-only.bin", "application/octet-stream", linkSize, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFile(owner.ID, linkSHA); err != nil {
		t.Fatal(err)
	}

	spaceSHA, spaceSize := put(t, s, "space-only content")
	if _, err := s.AddFile(member.ID, spaceSHA, "space.bin", "application/octet-stream", spaceSize, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(owner.ID, "reporting")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSpaceEvent(sp.ID, member.Email, "file", "", spaceSHA, "space.bin", "application/octet-stream", spaceSize); err != nil {
		t.Fatal(err)
	}

	consumers, err := s.TopStorageConsumers(10)
	if err != nil {
		t.Fatal(err)
	}
	var reported *StorageConsumer
	for i := range consumers {
		if consumers[i].AgentID == owner.ID {
			reported = &consumers[i]
			break
		}
	}
	wantBytes := fileSize + linkSize + spaceSize
	if reported == nil || reported.Files != 3 || reported.Bytes != wantBytes {
		t.Fatalf("owner storage report = %+v, want 3 distinct blobs / %d bytes", reported, wantBytes)
	}
	if used, err := s.StorageUsed(owner.ID); err != nil || used != reported.Bytes {
		t.Fatalf("StorageUsed=%d err=%v, report=%+v", used, err, reported)
	}
}

func TestInboxDefaultWindowContainsNewestMessages(t *testing.T) {
	s := newStore(t)
	a, _, _ := s.CreateAgent("newest-inbox", "", false)
	for i := 0; i < DefaultInboxListLimit+5; i++ {
		if _, err := s.AddMessage(Message{
			ID: fmt.Sprintf("msg-%03d", i), AgentID: a.ID, From: "x@example.com",
			Subject: fmt.Sprintf("%03d", i), ReceivedAt: int64(i + 1),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListInbox(a.ID, false, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != DefaultInboxListLimit || got[0].ID != "msg-005" || got[len(got)-1].ID != "msg-104" {
		t.Fatalf("newest window len=%d first=%q last=%q", len(got), got[0].ID, got[len(got)-1].ID)
	}
}

func TestAddMessageEvictsOnlyOldestReadMessagesTransactionally(t *testing.T) {
	s := newStore(t)
	a, _, _ := s.CreateAgent("inbox-eviction", "", false)
	add := func(id, body string, received int64) error {
		_, err := s.addMessageLimited(Message{
			ID: id, AgentID: a.ID, From: "x", Text: body, ReceivedAt: received,
		}, 3, 1<<20)
		return err
	}
	for i, id := range []string{"read-oldest", "read-newer", "unread"} {
		if err := add(id, "body", int64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkRead(a.ID, "read-oldest"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRead(a.ID, "read-newer"); err != nil {
		t.Fatal(err)
	}
	if err := add("replacement", "body", 4); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMessage(a.ID, "read-oldest"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest read message survived eviction: %v", err)
	}
	for _, id := range []string{"read-newer", "unread", "replacement"} {
		if _, err := s.GetMessage(a.ID, id); err != nil {
			t.Fatalf("message %q was lost: %v", id, err)
		}
	}

	// A failed replacement insert rolls back its tentative read-message
	// eviction, so capacity management cannot lose history on an unrelated DB
	// failure.
	if err := s.MarkRead(a.ID, "replacement"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_inbox_replacement
		BEFORE INSERT ON messages WHEN NEW.id='forced-failure'
		BEGIN SELECT RAISE(ABORT,'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := add("forced-failure", "body", 5); err == nil {
		t.Fatal("forced message insert unexpectedly succeeded")
	}
	for _, id := range []string{"read-newer", "replacement"} {
		if _, err := s.GetMessage(a.ID, id); err != nil {
			t.Fatalf("read message %q eviction was not rolled back: %v", id, err)
		}
	}
}

func TestAddMessageEvictsReadRowsForByteCapacityButPreservesUnread(t *testing.T) {
	s := newStore(t)
	a, _, _ := s.CreateAgent("inbox-byte-eviction", "", false)
	message := func(id string, received int64) Message {
		return Message{ID: id, AgentID: a.ID, From: "x", Text: strings.Repeat("x", 20), ReceivedAt: received}
	}
	// Each fixture consumes 27 accounted bytes (from + null to-list + body +
	// empty attachment JSON), so two fit below 60 while three do not.
	for i, id := range []string{"read", "unread"} {
		if _, err := s.addMessageLimited(message(id, int64(i+1)), 10, 60); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkRead(a.ID, "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.addMessageLimited(message("new", 3), 10, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMessage(a.ID, "read"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read byte-cap row survived: %v", err)
	}
	if _, err := s.GetMessage(a.ID, "unread"); err != nil {
		t.Fatalf("unread row was evicted: %v", err)
	}
	// With only unread rows left, another message must fail rather than discard
	// either one.
	if _, err := s.addMessageLimited(message("blocked", 4), 10, 50); !errors.Is(err, ErrInboxFull) {
		t.Fatalf("unread-full insert error = %v, want ErrInboxFull", err)
	}
}

func TestListReceiptsLimitReturnsNewestWindowInChainOrder(t *testing.T) {
	s := newStore(t)
	var actorReceipts []receipt.Receipt
	for i := 0; i < 5; i++ {
		actor := "alice@local"
		if i == 2 {
			actor = "bob@local" // actor filtering happens before the window.
		}
		r, err := s.AppendReceipt(actor, receipt.ActionUploaded, "", int64(i+1), fmt.Sprintf("event-%d", i), "")
		if err != nil {
			t.Fatal(err)
		}
		if actor == "alice@local" {
			actorReceipts = append(actorReceipts, r)
		}
	}

	got, err := s.ListReceipts("alice@local", 2)
	if err != nil {
		t.Fatal(err)
	}
	want := actorReceipts[len(actorReceipts)-2:]
	if len(got) != 2 || got[0].ID != want[0].ID || got[1].ID != want[1].ID {
		t.Fatalf("actor receipt window = %+v, want [%s %s]", got, want[0].ID, want[1].ID)
	}
	all, err := s.ListReceipts("", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Target != "event-3" || all[1].Target != "event-4" {
		t.Fatalf("global receipt window = %+v", all)
	}
}

func TestIdempotencyRecordsAreRequestBoundBoundedAndPruned(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("idempotency-store", "", false)
	if err != nil {
		t.Fatal(err)
	}
	record, created, err := s.BeginIdempotent(a.ID, "first", "hash-a")
	if err != nil || !created || record.Status != 0 {
		t.Fatalf("initial reservation created=%v record=%+v err=%v", created, record, err)
	}
	body := []byte("{\"ok\":true}\n")
	if err := s.CompleteIdempotent(a.ID, "first", "hash-a", 201, body); err != nil {
		t.Fatal(err)
	}
	record, created, err = s.BeginIdempotent(a.ID, "first", "hash-a")
	if err != nil || created || record.Status != 201 || !bytes.Equal(record.Response, body) {
		t.Fatalf("completed replay created=%v record=%+v err=%v", created, record, err)
	}
	if _, _, err := s.BeginIdempotent(a.ID, "first", "hash-b"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different request reused key: %v", err)
	}

	for i := 1; i < MaxIdempotencyRowsPerAgent; i++ {
		key := fmt.Sprintf("key-%03d", i)
		if _, created, err := s.BeginIdempotent(a.ID, key, "hash"); err != nil || !created {
			t.Fatalf("reserve %s created=%v err=%v", key, created, err)
		}
		if err := s.CompleteIdempotent(a.ID, key, "hash", 400, []byte("{\"error\":\"invalid\"}\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.BeginIdempotent(a.ID, "over-cap", "hash"); !errors.Is(err, ErrLimit) {
		t.Fatalf("idempotency cap error=%v, want ErrLimit", err)
	}
	if _, err := s.DB.Exec(`UPDATE idempotency SET created_at=1 WHERE agent_id=? AND key='first'`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.BeginIdempotent(a.ID, "after-prune", "hash"); err != nil || !created {
		t.Fatalf("expired-row replacement created=%v err=%v", created, err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM idempotency WHERE agent_id=?`, a.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != MaxIdempotencyRowsPerAgent {
		t.Fatalf("bounded idempotency rows=%d, want %d", count, MaxIdempotencyRowsPerAgent)
	}
}

func TestExpireFilesAndKeepAreLinearizable(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("expiry-race", "", false)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 100
	for i := 0; i < attempts; i++ {
		sha, size := put(t, s, fmt.Sprintf("expiry-race-%d", i))
		if _, err := s.AddFile(a.ID, sha, fmt.Sprintf("file-%03d", i), "text/plain", size, "upload", false, 1); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		keepResult := make(chan error, 1)
		expireResult := make(chan struct {
			files []File
			err   error
		}, 1)
		go func() {
			<-start
			_, err := s.KeepFile(a.ID, sha, 0)
			keepResult <- err
		}()
		go func() {
			<-start
			files, err := s.ExpireFiles(1)
			expireResult <- struct {
				files []File
				err   error
			}{files: files, err: err}
		}()
		close(start)
		keepErr := <-keepResult
		expired := <-expireResult
		if expired.err != nil {
			t.Fatal(expired.err)
		}
		switch {
		case keepErr == nil:
			if len(expired.files) != 0 {
				t.Fatalf("attempt %d: keeper succeeded but expiry returned %+v", i, expired.files)
			}
			f, err := s.FileBySHA(a.ID, sha)
			if err != nil || f.ExpiresAt != 0 {
				t.Fatalf("attempt %d: kept file=%+v err=%v", i, f, err)
			}
		case errors.Is(keepErr, ErrNotFound):
			if len(expired.files) != 1 || expired.files[0].SHA256 != sha {
				t.Fatalf("attempt %d: expiry won but returned %+v", i, expired.files)
			}
			if _, err := s.FileBySHA(a.ID, sha); !errors.Is(err, ErrNotFound) {
				t.Fatalf("attempt %d: expired file remained: %v", i, err)
			}
		default:
			t.Fatalf("attempt %d: keep error=%v", i, keepErr)
		}
	}
}

func TestDirectoryFiltersBeforeLimitClampsAndHidesPendingFleetCards(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 205; i++ {
		a, _, err := s.CreateAgent(fmt.Sprintf("dir-%03d", i), "", false)
		if err != nil {
			t.Fatal(err)
		}
		caps := []string{"other"}
		if i == 0 {
			caps = []string{"target"}
		}
		if err := s.SetCard(a.ID, "", caps, true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`UPDATE cards SET updated_at=? WHERE agent_id=?`, int64(i+1), a.ID); err != nil {
			t.Fatal(err)
		}
	}
	filtered, err := s.Directory("target", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].Name != "dir-000" {
		t.Fatalf("filtered directory=%+v, older match was lost behind limit", filtered)
	}
	all, err := s.Directory("", 1000)
	if err != nil || len(all) != 200 {
		t.Fatalf("clamped directory len=%d err=%v, want 200", len(all), err)
	}

	_, pending, _, err := s.CreatePersonWithAgent("hidden-person", "owner@example.com", "laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCard(pending.ID, "pending", []string{"target"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CardByName(pending.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending fleet card lookup=%v, want hidden", err)
	}
	if err := s.MarkOwnerVerified(pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CardByName(pending.Name); err != nil {
		t.Fatalf("approved fleet card remained hidden: %v", err)
	}
}

func TestUploadRequestFileInsertFailureDoesNotConsumeToken(t *testing.T) {
	s := newStore(t)
	a, _, _ := s.CreateAgent("request-atomic", "", false)
	sha, size := put(t, s, "request bytes")
	u, err := s.CreateUploadRequest(a.ID, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_request_file BEFORE INSERT ON files
		WHEN NEW.source='request' BEGIN SELECT RAISE(ABORT,'forced file failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, won, err := s.UseUploadRequestWithFile(u.Token, a.ID, sha, "x.bin", "application/octet-stream", size, now()+60); err == nil || won {
		t.Fatalf("forced insert result won=%v err=%v", won, err)
	}
	if _, err := s.GetUploadRequest(u.Token); err != nil {
		t.Fatalf("token was consumed by rolled-back file insert: %v", err)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER fail_request_file`); err != nil {
		t.Fatal(err)
	}
	if _, won, err := s.UseUploadRequestWithFile(u.Token, a.ID, sha, "x.bin", "application/octet-stream", size, now()+60); err != nil || !won {
		t.Fatalf("retry won=%v err=%v", won, err)
	}
}

func TestConcurrentDurableResourceCapsDoNotOversubscribe(t *testing.T) {
	t.Run("active links", func(t *testing.T) {
		s := newStore(t)
		a, _, _ := s.CreateAgent("link-cap", "", false)
		sha, size := put(t, s, "link cap")
		tx, _ := s.DB.Begin()
		for i := 0; i < MaxActiveLinksPerAgent-1; i++ {
			if _, err := tx.Exec(`INSERT INTO links(token,agent_id,sha256,name,mime,size,expires_at,created_at)
				VALUES(?,?,?,?,?,?,?,?)`, fmt.Sprintf("cap-link-%04d", i), a.ID, sha, "x", "text/plain", size, now()+3600, now()); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func() {
				<-start
				_, err := s.CreateLink(a.ID, sha, "x", "text/plain", size, false, time.Hour)
				errs <- err
			}()
		}
		close(start)
		winners := 0
		for i := 0; i < 8; i++ {
			if err := <-errs; err == nil {
				winners++
			} else if !errors.Is(err, ErrLimit) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("link winners=%d, want 1", winners)
		}
	})

	t.Run("upload requests", func(t *testing.T) {
		s := newStore(t)
		a, _, _ := s.CreateAgent("request-cap", "", false)
		for i := 0; i < MaxUploadRequestsPerAgent-1; i++ {
			if _, err := s.CreateUploadRequest(a.ID, "", time.Hour); err != nil {
				t.Fatal(err)
			}
		}
		start := make(chan struct{})
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func() {
				<-start
				_, err := s.CreateUploadRequest(a.ID, "", time.Hour)
				errs <- err
			}()
		}
		close(start)
		winners := 0
		for i := 0; i < 8; i++ {
			if err := <-errs; err == nil {
				winners++
			} else if !errors.Is(err, ErrLimit) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("request winners=%d, want 1", winners)
		}
	})

	t.Run("webhooks", func(t *testing.T) {
		s := newStore(t)
		a, _, _ := s.CreateAgent("webhook-cap", "", false)
		for i := 0; i < MaxWebhooksPerAgent-1; i++ {
			if _, err := s.CreateWebhook(a.ID, fmt.Sprintf("https://example.test/%d", i), "secret", "*"); err != nil {
				t.Fatal(err)
			}
		}
		start := make(chan struct{})
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func(i int) {
				<-start
				_, err := s.CreateWebhook(a.ID, fmt.Sprintf("https://race.test/%d", i), "secret", "*")
				errs <- err
			}(i)
		}
		close(start)
		winners := 0
		for i := 0; i < 8; i++ {
			if err := <-errs; err == nil {
				winners++
			} else if !errors.Is(err, ErrLimit) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("webhook winners=%d, want 1", winners)
		}
	})

	t.Run("connect queue", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.CreateConnectInstance("queue-cap"); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func() {
				<-start
				errs <- s.EnqueueConnectMail("queue-cap", []string{"a@x"}, []byte("x"), 1, 1024)
			}()
		}
		close(start)
		winners := 0
		for i := 0; i < 8; i++ {
			if err := <-errs; err == nil {
				winners++
			} else if !errors.Is(err, ErrQueueFull) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("queue winners=%d, want 1", winners)
		}
	})

	t.Run("inbox", func(t *testing.T) {
		s := newStore(t)
		a, _, _ := s.CreateAgent("inbox-cap", "", false)
		tx, _ := s.DB.Begin()
		for i := 0; i < MaxInboxMessagesPerAgent-1; i++ {
			if _, err := tx.Exec(`INSERT INTO messages(id,agent_id,from_addr,received_at)
				VALUES(?,?,?,?)`, fmt.Sprintf("cap-msg-%05d", i), a.ID, "x@example.test", i+1); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			go func(i int) {
				<-start
				_, err := s.AddMessage(Message{ID: fmt.Sprintf("race-msg-%02d", i), AgentID: a.ID, From: "x@example.test"})
				errs <- err
			}(i)
		}
		close(start)
		winners := 0
		for i := 0; i < 8; i++ {
			if err := <-errs; err == nil {
				winners++
			} else if !errors.Is(err, ErrInboxFull) {
				t.Fatal(err)
			}
		}
		if winners != 1 {
			t.Fatalf("inbox winners=%d, want 1", winners)
		}
	})
}

func TestConnectMailCannotOutliveItsInstance(t *testing.T) {
	s := newStore(t)
	if err := s.EnqueueConnectMail("missing", []string{"a@x"}, []byte("x"), 10, 1024); !errors.Is(err, ErrNotFound) {
		t.Fatalf("enqueue for missing instance: got %v, want ErrNotFound", err)
	}
	if mail, err := s.ListConnectMail("missing", 0); err != nil || len(mail) != 0 {
		t.Fatalf("orphan mail after rejected enqueue: mail=%v err=%v", mail, err)
	}

	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("reap-race-%02d", i)
		if _, err := s.CreateConnectInstance(name); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		enqueueErr := make(chan error, 1)
		reapErr := make(chan error, 1)
		go func() {
			<-start
			enqueueErr <- s.EnqueueConnectMail(name, []string{"a@x"}, []byte("x"), 10, 1024)
		}()
		go func() {
			<-start
			_, err := s.ReapConnectInstances(0, 0)
			reapErr <- err
		}()
		close(start)
		if err := <-enqueueErr; err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("iteration %d enqueue: %v", i, err)
		}
		if err := <-reapErr; err != nil {
			t.Fatalf("iteration %d reap: %v", i, err)
		}
		if _, err := s.ConnectInstanceByName(name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("iteration %d instance survived reap: %v", i, err)
		}
		mail, err := s.ListConnectMail(name, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(mail) != 0 {
			t.Fatalf("iteration %d left %d orphan mail rows", i, len(mail))
		}
	}
}

func TestInstanceRenameLinearizesWithAgentCreation(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 32; i++ {
		domain := fmt.Sprintf("instance-%02d.example.test", i)
		start := make(chan struct{})
		agentResult := make(chan Agent, 1)
		createErr := make(chan error, 1)
		renameErr := make(chan error, 1)
		go func(i int) {
			<-start
			agent, _, err := s.CreateAgent(fmt.Sprintf("rename-race-%02d", i), "", false)
			agentResult <- agent
			createErr <- err
		}(i)
		go func() {
			<-start
			renameErr <- s.RenameInstance(domain)
		}()
		close(start)
		agent := <-agentResult
		if err := <-createErr; err != nil {
			t.Fatalf("iteration %d create: %v", i, err)
		}
		if err := <-renameErr; err != nil {
			t.Fatalf("iteration %d rename: %v", i, err)
		}
		stored, err := s.AgentByID(agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := stored.Name + "@" + domain
		if stored.Email != want {
			t.Fatalf("iteration %d stored email=%q, want %q", i, stored.Email, want)
		}
		if got := s.Instance(); got != domain {
			t.Fatalf("iteration %d instance=%q, want %q", i, got, domain)
		}
	}
}

func TestConcurrentWebhookClaimsReturnEachDeliveryOnce(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("webhook-claim", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWebhook(a.ID, "https://example.test/hook", "secret", "*"); err != nil {
		t.Fatal(err)
	}
	const deliveries = 20
	for i := 0; i < deliveries; i++ {
		if err := s.EnqueueDeliveries(a.ID, "message.received", []byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan []WebhookDelivery, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			<-start
			claimed, err := s.ClaimDueDeliveries(5)
			results <- claimed
			errs <- err
		}()
	}
	close(start)
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		claimed := <-results
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		for _, delivery := range claimed {
			if seen[delivery.ID] {
				t.Fatalf("delivery %s was claimed twice", delivery.ID)
			}
			seen[delivery.ID] = true
		}
	}
	if len(seen) != deliveries {
		t.Fatalf("unique claimed deliveries=%d, want %d", len(seen), deliveries)
	}
	if more, err := s.ClaimDueDeliveries(5); err != nil || len(more) != 0 {
		t.Fatalf("claim after drain=%d err=%v", len(more), err)
	}
}

func TestConcurrentSpaceMemberCapIsAtomicAndIdempotent(t *testing.T) {
	s := newStore(t)
	owner, _, err := s.CreateAgent("member-cap-owner", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(owner.ID, "bounded membership")
	if err != nil {
		t.Fatal(err)
	}

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	// The owner is member one. Seed through member 499, leaving exactly one
	// slot for the concurrent candidates below.
	const candidateCount = 8
	seedMembers := MaxMembersPerSpace - 2
	for i := 0; i < seedMembers+candidateCount; i++ {
		id := fmt.Sprintf("member-cap-id-%03d", i)
		name := fmt.Sprintf("member-cap-%03d", i)
		if _, err := tx.Exec(`INSERT INTO agents(id,name,email,key_hash,created_at)
			VALUES(?,?,?,?,?)`, id, name, name+"@local", "key-"+name, now()); err != nil {
			t.Fatal(err)
		}
		if i < seedMembers {
			if _, err := tx.Exec(`INSERT INTO space_members(space_id,agent_id,role,joined_at)
				VALUES(?,?,'member',?)`, sp.ID, id, now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	type result struct {
		id    string
		added bool
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, candidateCount)
	for i := seedMembers; i < seedMembers+candidateCount; i++ {
		id := fmt.Sprintf("member-cap-id-%03d", i)
		go func(id string) {
			<-start
			ev, added, err := s.AddSpaceMember(sp.ID, id, "member", id+"@local")
			if err == nil && added && (ev.Kind != "join" || ev.Actor != id+"@local") {
				err = fmt.Errorf("wrong join event: %+v", ev)
			}
			results <- result{id: id, added: added, err: err}
		}(id)
	}
	close(start)
	winners := []string{}
	for i := 0; i < candidateCount; i++ {
		result := <-results
		if result.err == nil && result.added {
			winners = append(winners, result.id)
		} else if !errors.Is(result.err, ErrLimit) {
			t.Fatalf("unexpected member-cap error: %v", result.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("member-cap winners=%v, want exactly one", winners)
	}
	var members int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_members WHERE space_id=?`, sp.ID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if members != MaxMembersPerSpace {
		t.Fatalf("members=%d, want %d", members, MaxMembersPerSpace)
	}
	if _, added, err := s.AddSpaceMember(sp.ID, winners[0], "member", winners[0]+"@local"); err != nil {
		t.Fatalf("idempotent re-add at capacity failed: %v", err)
	} else if added {
		t.Fatal("idempotent re-add reported a membership change")
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=? AND kind='join'`, sp.ID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if members != 1 {
		t.Fatalf("join events=%d, want one for the sole successful candidate", members)
	}
}

func TestSpaceMembershipAndEventsRollbackTogether(t *testing.T) {
	s := newStore(t)
	owner, _, err := s.CreateAgent("membership-rollback-owner", "", false)
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := s.CreateAgent("membership-rollback-target", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(owner.ID, "atomic membership")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.Exec(`CREATE TRIGGER reject_join_event BEFORE INSERT ON space_events
		WHEN NEW.kind='join' BEGIN SELECT RAISE(ABORT,'forced join failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, added, err := s.AddSpaceMember(sp.ID, target.ID, "member", target.Email); err == nil {
		t.Fatal("forced join-event failure unexpectedly succeeded")
	} else if added {
		t.Fatal("failed join transaction reported a membership change")
	}
	if _, member := s.SpaceMemberRole(sp.ID, target.ID); member {
		t.Fatal("membership survived its failed join event")
	}
	var events int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=?`, sp.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("events=%d after failed join, want 0", events)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER reject_join_event`); err != nil {
		t.Fatal(err)
	}
	if ev, added, err := s.AddSpaceMember(sp.ID, target.ID, "member", target.Email); err != nil || !added || ev.Kind != "join" {
		t.Fatalf("successful add: event=%+v added=%v err=%v", ev, added, err)
	}
	var role string
	var joinedAt int64
	if err := s.DB.QueryRow(`SELECT role,joined_at FROM space_members WHERE space_id=? AND agent_id=?`,
		sp.ID, target.ID).Scan(&role, &joinedAt); err != nil {
		t.Fatal(err)
	}
	if _, added, err := s.AddSpaceMember(sp.ID, target.ID, "owner", "different-actor@local"); err != nil || added {
		t.Fatalf("idempotent re-add: added=%v err=%v", added, err)
	}
	var roleAfter string
	var joinedAtAfter int64
	if err := s.DB.QueryRow(`SELECT role,joined_at FROM space_members WHERE space_id=? AND agent_id=?`,
		sp.ID, target.ID).Scan(&roleAfter, &joinedAtAfter); err != nil {
		t.Fatal(err)
	}
	if roleAfter != role || joinedAtAfter != joinedAt {
		t.Fatalf("re-add changed membership: role/joined_at=%q/%d, want %q/%d",
			roleAfter, joinedAtAfter, role, joinedAt)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=?`, sp.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("idempotent re-add emitted another event: count=%d", events)
	}

	if _, err := s.DB.Exec(`CREATE TRIGGER reject_leave_event BEFORE INSERT ON space_events
		WHEN NEW.kind='leave' BEGIN SELECT RAISE(ABORT,'forced leave failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveSpaceMember(sp.ID, target.ID, target.Email); err == nil {
		t.Fatal("forced leave-event failure unexpectedly succeeded")
	}
	if _, member := s.SpaceMemberRole(sp.ID, target.ID); !member {
		t.Fatal("failed leave event still removed membership")
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=?`, sp.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("events=%d after failed leave, want original join only", events)
	}
	if _, err := s.DB.Exec(`DROP TRIGGER reject_leave_event`); err != nil {
		t.Fatal(err)
	}
	if ev, err := s.RemoveSpaceMember(sp.ID, target.ID, target.Email); err != nil || ev.Kind != "leave" {
		t.Fatalf("successful remove: event=%+v err=%v", ev, err)
	}
	if _, member := s.SpaceMemberRole(sp.ID, target.ID); member {
		t.Fatal("membership survived successful leave")
	}
}

func TestConcurrentSpaceMembershipTransitionsEmitOneEvent(t *testing.T) {
	s := newStore(t)
	owner, _, err := s.CreateAgent("membership-race-owner", "", false)
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := s.CreateAgent("membership-race-target", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(owner.ID, "membership race")
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 12
	start := make(chan struct{})
	type addResult struct {
		added bool
		err   error
	}
	adds := make(chan addResult, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			_, added, err := s.AddSpaceMember(sp.ID, target.ID, "member", target.Email)
			adds <- addResult{added: added, err: err}
		}()
	}
	close(start)
	addedCount := 0
	for i := 0; i < attempts; i++ {
		result := <-adds
		if result.err != nil {
			t.Fatalf("concurrent add failed: %v", result.err)
		}
		if result.added {
			addedCount++
		}
	}
	if addedCount != 1 {
		t.Fatalf("membership changes=%d, want 1", addedCount)
	}

	start = make(chan struct{})
	removes := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			_, err := s.RemoveSpaceMember(sp.ID, target.ID, target.Email)
			removes <- err
		}()
	}
	close(start)
	removed, missing := 0, 0
	for i := 0; i < attempts; i++ {
		switch err := <-removes; {
		case err == nil:
			removed++
		case errors.Is(err, ErrNotFound):
			missing++
		default:
			t.Fatalf("concurrent remove failed: %v", err)
		}
	}
	if removed != 1 || missing != attempts-1 {
		t.Fatalf("remove outcomes: removed=%d missing=%d", removed, missing)
	}
	var joins, leaves int
	if err := s.DB.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE kind='join'),
		COUNT(*) FILTER (WHERE kind='leave')
		FROM space_events WHERE space_id=?`, sp.ID).Scan(&joins, &leaves); err != nil {
		t.Fatal(err)
	}
	if joins != 1 || leaves != 1 {
		t.Fatalf("membership events: join=%d leave=%d, want 1/1", joins, leaves)
	}
	if _, member := s.SpaceMemberRole(sp.ID, target.ID); member {
		t.Fatal("target remains a member after the successful remove")
	}
}

func TestSpaceEventsUseAtomicRollingRetentionWindow(t *testing.T) {
	s := newStore(t)
	owner, _, err := s.CreateAgent("rolling-space-owner", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(owner.ID, "rolling history")
	if err != nil {
		t.Fatal(err)
	}
	prunedSHA, _ := put(t, s, "old file offer")
	retainedSHA, _ := put(t, s, "new file offer")

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxEventsPerSpace; i++ {
		kind, sha := "message", ""
		if i == 0 {
			kind, sha = "file", prunedSHA
		} else if i == MaxEventsPerSpace-1 {
			kind, sha = "file", retainedSHA
		}
		if _, err := tx.Exec(`INSERT INTO space_events(id,space_id,actor,kind,text,sha256,created_at)
			VALUES(?,?,?,?,?,?,?)`, fmt.Sprintf("seed-event-%05d", i), sp.ID, owner.Email, kind, "seed", sha, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	type appendResult struct {
		id  string
		err error
	}
	results := make(chan appendResult, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			<-start
			ev, err := s.AddSpaceEvent(sp.ID, owner.Email, "message", fmt.Sprintf("new-%d", i), "", "", "", 0)
			results <- appendResult{id: ev.ID, err: err}
		}(i)
	}
	close(start)
	appended := map[string]bool{}
	for i := 0; i < 8; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("rolling append failed: %v", result.err)
		}
		appended[result.id] = true
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=?`, sp.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != MaxEventsPerSpace {
		t.Fatalf("retained event count=%d, want %d", count, MaxEventsPerSpace)
	}
	for i := 0; i < 8; i++ {
		var exists int
		err := s.DB.QueryRow(`SELECT 1 FROM space_events WHERE id=?`, fmt.Sprintf("seed-event-%05d", i)).Scan(&exists)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("old event %d was not pruned: %v", i, err)
		}
	}
	for id := range appended {
		var exists int
		if err := s.DB.QueryRow(`SELECT 1 FROM space_events WHERE id=?`, id).Scan(&exists); err != nil {
			t.Fatalf("appended event %s missing: %v", id, err)
		}
	}

	// Pruning a file offer releases its blob, while a retained offer continues
	// to protect its bytes from orphan collection.
	if _, err := s.DB.Exec(`UPDATE blobs SET created_at=1 WHERE sha256 IN (?,?)`, prunedSHA, retainedSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteOrphanBlobs(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenBlob(prunedSHA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned file offer still pins blob: %v", err)
	}
	retained, err := s.OpenBlob(retainedSHA)
	if err != nil {
		t.Fatalf("retained file offer lost blob: %v", err)
	}
	retained.Close()

	// If the append fails after the trim, the transaction must restore the
	// previous oldest event and retain exactly the same window.
	var oldestBefore int64
	if err := s.DB.QueryRow(`SELECT MIN(seq) FROM space_events WHERE space_id=?`, sp.ID).Scan(&oldestBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_rolling_append BEFORE INSERT ON space_events
		WHEN NEW.text='forced rollback' BEGIN SELECT RAISE(ABORT,'forced append failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSpaceEvent(sp.ID, owner.Email, "message", "forced rollback", "", "", "", 0); err == nil {
		t.Fatal("forced rolling append unexpectedly succeeded")
	}
	var oldestAfter int64
	if err := s.DB.QueryRow(`SELECT COUNT(*),MIN(seq) FROM space_events WHERE space_id=?`, sp.ID).Scan(&count, &oldestAfter); err != nil {
		t.Fatal(err)
	}
	if count != MaxEventsPerSpace || oldestAfter != oldestBefore {
		t.Fatalf("failed append changed window: count=%d oldest=%d, want %d/%d",
			count, oldestAfter, MaxEventsPerSpace, oldestBefore)
	}
}

func TestOrphanGCRestoresBytesWhenMetadataDeleteFails(t *testing.T) {
	s := newStore(t)
	sha, _ := put(t, s, "unlink failure")
	if _, err := s.DB.Exec(`UPDATE blobs SET created_at=1 WHERE sha256=?`, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_blob_delete BEFORE DELETE ON blobs
		BEGIN SELECT RAISE(ABORT,'forced metadata failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteOrphanBlobs(); err == nil {
		t.Fatal("forced metadata failure unexpectedly succeeded")
	}
	var rows int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM blobs WHERE sha256=?`, sha).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("blob metadata rows=%d err=%v, want retained", rows, err)
	}
	f, err := s.OpenBlob(sha)
	if err != nil {
		t.Fatalf("blob bytes were not restored after DB failure: %v", err)
	}
	f.Close()
}

func TestAmbiguousBlobCommitUsesMetadataBeforeRestoringTomb(t *testing.T) {
	s := newStore(t)
	sha, _ := put(t, s, "ambiguous commit")
	src := s.blobPath(sha)
	tombDir := filepath.Join(s.dataDir, "blob-tombs")
	if err := os.MkdirAll(tombDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tomb := filepath.Join(tombDir, sha+".test")
	if err := os.Rename(src, tomb); err != nil {
		t.Fatal(err)
	}
	fakeCommitErr := errors.New("ambiguous commit result")
	committed, err := s.resolveAmbiguousBlobCommit(sha, src, tomb, true, fakeCommitErr)
	if committed || !errors.Is(err, fakeCommitErr) {
		t.Fatalf("surviving metadata resolved committed=%v err=%v", committed, err)
	}
	if f, err := s.OpenBlob(sha); err != nil {
		t.Fatalf("surviving metadata did not restore bytes: %v", err)
	} else {
		f.Close()
	}

	if err := os.Rename(src, tomb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM blobs WHERE sha256=?`, sha); err != nil {
		t.Fatal(err)
	}
	committed, err = s.resolveAmbiguousBlobCommit(sha, src, tomb, true, fakeCommitErr)
	if err != nil || !committed {
		t.Fatalf("missing metadata resolved committed=%v err=%v", committed, err)
	}
	if _, err := os.Stat(tomb); !os.IsNotExist(err) {
		t.Fatalf("confirmed committed tomb remains: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("confirmed committed bytes were restored: %v", err)
	}
}
