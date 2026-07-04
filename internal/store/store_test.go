package store

import (
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, _, err := Open(t.TempDir(), "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func put(t *testing.T, s *Store, content string) (sha string, size int64) {
	t.Helper()
	sha, size, err := s.PutBlob(strings.NewReader(content), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return sha, size
}

// survivesGC ages every blob past the grace window, runs orphan GC, and reports
// whether sha's bytes remain — i.e. whether some file or active link still
// references it. The whole reference model is computed on demand, so this is the
// only observable that matters (there is no refcount to inspect).
func survivesGC(t *testing.T, s *Store, sha string) bool {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE blobs SET created_at=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteOrphanBlobs(); err != nil {
		t.Fatal(err)
	}
	_, err := s.OpenBlob(sha)
	return err == nil
}

// A link may be closed exactly once; further closes (burn racing revoke, the
// janitor racing either) lose the race and are no-ops. And a blob a file still
// references must never be reclaimed when a separate link over it closes.
func TestCloseLinkKeepsReferencedBlob(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "shared bytes")
	if _, err := s.AddFile(a.ID, sha, "f.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	l, err := s.CreateLink(a.ID, sha, "f.txt", "text/plain", size, true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeLink(l.Token); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if _, err := s.BurnLink(l.Token); err != ErrNotFound {
		t.Fatalf("second close should lose: got %v", err)
	}
	if _, err := s.RevokeLink(l.Token); err != ErrNotFound {
		t.Fatalf("third close should lose: got %v", err)
	}
	if !survivesGC(t, s, sha) {
		t.Fatal("blob GC'd while a file still references it")
	}
}

// A blob reachable only through a link is kept alive while the link is active
// and reclaimed once it closes.
func TestLinkOnlyBlobReclaimedAfterClose(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "link only")
	l, err := s.CreateLink(a.ID, sha, "f.txt", "text/plain", size, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !survivesGC(t, s, sha) {
		t.Fatal("an active link must keep its blob alive")
	}
	if _, err := s.RevokeLink(l.Token); err != nil {
		t.Fatal(err)
	}
	if survivesGC(t, s, sha) {
		t.Fatal("blob survived after its only link closed")
	}
}

// A blob shared by two agents must survive one agent deleting (and double-
// deleting) its copy, and be reclaimed only once no agent references it.
func TestSharedBlobSurvivesOneAgentDelete(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.CreateAgent("bob", "", true)
	if err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "everyone has this")
	if _, err := s.AddFile(a.ID, sha, "f.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFile(b.ID, sha, "f.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFile(a.ID, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFile(a.ID, sha); err != ErrNotFound {
		t.Fatalf("second delete should be NotFound, got %v", err)
	}
	if !survivesGC(t, s, sha) {
		t.Fatal("bob's copy must survive alice's delete")
	}
	if _, err := s.DeleteFile(b.ID, sha); err != nil {
		t.Fatal(err)
	}
	if survivesGC(t, s, sha) {
		t.Fatal("blob should be reclaimed once no agent references it")
	}
}

// DeleteAgent must succeed even when the agent has registered a webhook: the
// webhooks.agent_id FK is ON DELETE CASCADE. Regression test for the delete
// path throwing a FK violation (and rolling back) on any agent with a webhook.
func TestDeleteAgentCascadesWebhooks(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWebhook(a.ID, "https://example.test/hook", "whsec_x", "*"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteAgent(a.ID); err != nil {
		t.Fatalf("DeleteAgent with a webhook failed (FK cascade regression): %v", err)
	}
	whs, err := s.ListWebhooks(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(whs) != 0 {
		t.Fatalf("webhooks survived agent deletion: %d", len(whs))
	}
}

// The orphan GC must not touch young blobs (the ref lands moments after
// PutBlob) and must delete the row before the disk bytes.
func TestOrphanGCGraceAndReRef(t *testing.T) {
	s := newStore(t)
	a, _, err := s.CreateAgent("alice", "", true)
	if err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "fresh orphan")

	// refs=0 but brand new: grace period must protect it.
	if n, err := s.DeleteOrphanBlobs(); err != nil || n != 0 {
		t.Fatalf("GC removed a blob inside the grace period (n=%d err=%v)", n, err)
	}
	if _, err := s.OpenBlob(sha); err != nil {
		t.Fatalf("young orphan lost its bytes: %v", err)
	}

	// Re-referenced after aging: still must survive.
	if _, err := s.AddFile(a.ID, sha, "f.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE blobs SET created_at=1 WHERE sha256=?`, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteOrphanBlobs(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenBlob(sha); err != nil {
		t.Fatalf("referenced blob was GC'd: %v", err)
	}

	// Fully orphaned and aged: now it goes, row and disk both.
	if _, err := s.DeleteFile(a.ID, sha); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteOrphanBlobs(); err != nil || n != 1 {
		t.Fatalf("expected exactly one GC'd blob, got n=%d err=%v", n, err)
	}
	if _, err := s.OpenBlob(sha); err == nil {
		t.Fatal("orphan blob survived GC")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM blobs WHERE sha256=?`, sha).Scan(&count); err != nil || count != 0 {
		t.Fatalf("blob row survived GC (count=%d err=%v)", count, err)
	}
}
