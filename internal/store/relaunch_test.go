package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/s3"
	"github.com/shehryarsaroya/agenttransfer/internal/s3/s3test"
)

func openRemote(t *testing.T) (*Store, *s3test.Fake) {
	t.Helper()
	st, _, err := Open(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fake := s3test.New()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	st.SetRemote(&s3.Client{Endpoint: srv.URL, Bucket: "blobs", AccessKey: "AK", SecretKey: "SK", HTTP: srv.Client()})
	return st, fake
}

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestRemotePutDedupReadAndGC(t *testing.T) {
	st, fake := openRemote(t)
	small := []byte("hello remote")
	sha, size, err := st.PutBlob(bytes.NewReader(small), 1<<20)
	if err != nil || sha != hexSHA(small) || size != int64(len(small)) {
		t.Fatalf("put small: %s %d %v", sha, size, err)
	}
	// Same content again: deduplicated onto the first object.
	sha2, _, err := st.PutBlob(bytes.NewReader(small), 1<<20)
	if err != nil || sha2 != sha || fake.Objects() != 1 {
		t.Fatalf("dedup: %s objects=%d err=%v", sha2, fake.Objects(), err)
	}
	// Multipart: just over two parts, with a short tail.
	big := make([]byte, 2*remotePartSize+12345)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	bsha, bsize, err := st.PutBlob(bytes.NewReader(big), int64(len(big)))
	if err != nil || bsha != hexSHA(big) || bsize != int64(len(big)) {
		t.Fatalf("put big: %d %v", bsize, err)
	}
	if fake.Objects() != 2 {
		t.Fatalf("objects = %d, want 2", fake.Objects())
	}
	// Over the limit fails and leaves nothing behind.
	if _, _, err := st.PutBlob(bytes.NewReader(big), int64(len(big))-1); !errors.Is(err, ErrQuota) {
		t.Fatalf("over limit: %v", err)
	}
	if fake.Objects() != 2 {
		t.Fatalf("over-limit upload leaked an object: %v", fake.Keys())
	}
	r, n, err := st.BlobReader(context.Background(), bsha)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if n != int64(len(big)) || !bytes.Equal(got, big) {
		t.Fatal("read back mismatch")
	}
	if _, err := st.OpenBlob(bsha); !errors.Is(err, ErrRemoteBlob) {
		t.Fatalf("OpenBlob in remote mode: %v", err)
	}
	u, err := st.BlobURL(sha, "rapport final.pdf", "application/pdf", time.Minute)
	if err != nil || !strings.Contains(u, "response-content-disposition") {
		t.Fatalf("blob url %q %v", u, err)
	}

	// Reference the small blob from a file; age both rows past the grace
	// window; GC removes only the unreferenced big one, row and object.
	a, _, err := st.CreateAgent("gc-owner", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddFile(a.ID, sha, "keep.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE blobs SET created_at=?`, now()-3600); err != nil {
		t.Fatal(err)
	}
	n2, err := st.DeleteOrphanBlobs()
	if err != nil || n2 != 1 {
		t.Fatalf("gc: %d %v", n2, err)
	}
	if fake.Objects() != 1 {
		t.Fatalf("gc left objects %v", fake.Keys())
	}
	var tombs int
	st.DB.QueryRow(`SELECT COUNT(*) FROM object_tombs`).Scan(&tombs)
	if tombs != 0 {
		t.Fatalf("tombs not drained: %d", tombs)
	}
	if _, _, err := st.BlobReader(context.Background(), bsha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("collected blob still readable: %v", err)
	}
}

func verifiedPerson(t *testing.T, st *Store, email string) Person {
	t.Helper()
	p, err := st.CreateVerifiedPerson(email, "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDriveSharedAcrossFleetAndSurvivesDisconnect(t *testing.T) {
	st, _, err := Open(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetInstance("example.test")
	p := verifiedPerson(t, st, "Dana.Smith@Example.com")
	if p.Handle != "dana-smith" || p.Email != "dana.smith@example.com" {
		t.Fatalf("person %+v", p)
	}
	chat, _, err := st.CreateApprovedAgentForPerson(p, "chatgpt")
	if err != nil || !chat.OwnerVerified || chat.Name != "dana-smith+chatgpt" {
		t.Fatalf("chat agent %+v %v", chat, err)
	}
	if _, _, err := st.CreateApprovedAgentForPerson(p, "drive"); err == nil {
		t.Fatal("drive tag must be reserved")
	}
	drive, err := st.DriveForPerson(p.ID)
	if err != nil || !drive.IsDrive() || !drive.OwnerVerified {
		t.Fatalf("drive %+v %v", drive, err)
	}
	again, _ := st.DriveForPerson(p.ID)
	if again.ID != drive.ID {
		t.Fatal("drive must be a singleton")
	}
	fleet, _ := st.AgentsByPerson(p.ID, true)
	if len(fleet) != 1 || fleet[0].ID != chat.ID {
		t.Fatalf("drive leaked into fleet listing: %+v", fleet)
	}
	sha, size, _ := st.PutBlob(strings.NewReader("drive bytes"), 1<<20)
	if _, err := st.AddFile(drive.ID, sha, "notes.md", "text/markdown", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	// Disconnecting ChatGPT (deleting its agent) keeps the drive's files.
	if _, _, err := st.DeleteAgent(chat.ID); err != nil {
		t.Fatal(err)
	}
	files, _ := st.ListFiles(drive.ID)
	if len(files) != 1 {
		t.Fatalf("drive lost files on disconnect: %d", len(files))
	}
	// A drive can never authenticate.
	if _, err := st.AgentByKey(""); err == nil {
		t.Fatal("empty key resolved")
	}
	n, _ := st.CountAgentsByOwner(p.Email)
	if n != 0 {
		t.Fatalf("drive counted toward the mailbox cap: %d", n)
	}
}

func TestMergeFolderIntoDrive(t *testing.T) {
	st, _, _ := Open(t.TempDir(), "")
	defer st.Close()
	p := verifiedPerson(t, st, "m@example.com")
	pending, _, err := st.CreateAgentForPerson(p, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	drive, _ := st.DriveForPerson(p.ID)
	s1, z1, _ := st.PutBlob(strings.NewReader("one"), 100)
	s2, z2, _ := st.PutBlob(strings.NewReader("two"), 100)
	st.AddFile(pending.ID, s1, "a.txt", "text/plain", z1, "upload", true, now()+3600)
	st.AddFile(pending.ID, s2, "b.txt", "text/plain", z2, "upload", true, now()+3600)
	st.AddFile(drive.ID, s2, "b.txt", "text/plain", z2, "upload", true, 0) // duplicate
	if _, err := st.CreateLink(pending.ID, s1, "a.txt", "text/plain", z1, false, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.MergeFolderIntoDrive(pending.ID, drive.ID); err != nil {
		t.Fatal(err)
	}
	files, _ := st.ListFiles(drive.ID)
	if len(files) != 2 {
		t.Fatalf("drive has %d files, want 2", len(files))
	}
	for _, f := range files {
		if f.ExpiresAt != 0 {
			t.Fatalf("claimed file kept its scratch expiry: %+v", f)
		}
	}
	left, _ := st.ListFiles(pending.ID)
	links, _ := st.ListLinks(drive.ID)
	if len(left) != 0 || len(links) != 1 {
		t.Fatalf("leftover files=%d drive links=%d", len(left), len(links))
	}
}

func TestUploadSessionsQuotaAndTransitions(t *testing.T) {
	st, _, _ := Open(t.TempDir(), "")
	defer st.Close()
	a, _, _ := st.CreateAgent("uploader", "", false)
	u, err := st.CreateUploadSession(UploadSession{FolderID: a.ID, ActorID: a.ID, Name: "x.bin",
		MIME: "application/octet-stream", Size: 500, ObjectKey: "o/1", ExpiresAt: now() + 60})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := st.PendingUploadBytes(a.ID); n != 500 {
		t.Fatalf("pending bytes %d", n)
	}
	won, _ := st.TransitionUpload(u.ID, UploadPending, UploadVerifying, "", "")
	lost, _ := st.TransitionUpload(u.ID, UploadPending, UploadVerifying, "", "")
	if !won || lost {
		t.Fatalf("transition race: won=%v lost=%v", won, lost)
	}
	st.TransitionUpload(u.ID, UploadVerifying, UploadDone, "", "abc")
	got, _ := st.GetUploadSession(u.ID)
	if got.Status != UploadDone || got.SHA256 != "abc" || got.CompletedAt == 0 {
		t.Fatalf("session %+v", got)
	}
	if n, _ := st.PendingUploadBytes(a.ID); n != 0 {
		t.Fatalf("done session still charged: %d", n)
	}
	mp := UploadSession{S3UploadID: "x", PartSize: 100, Size: 250}
	if !mp.Multipart() || mp.Parts() != 3 {
		t.Fatalf("parts = %d", mp.Parts())
	}
}

func TestLoginSessionsPasswordsAndOAuthLifecycle(t *testing.T) {
	st, _, _ := Open(t.TempDir(), "")
	defer st.Close()
	tok, err := st.CreateLoginToken("Who@Example.com", "/account", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if e, _, err := st.PeekLoginToken(tok); err != nil || e != "who@example.com" {
		t.Fatalf("peek %q %v", e, err)
	}
	if e, next, err := st.ConsumeLoginToken(tok); err != nil || e != "who@example.com" || next != "/account" {
		t.Fatalf("consume %q %q %v", e, next, err)
	}
	if _, _, err := st.ConsumeLoginToken(tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("login link reusable: %v", err)
	}
	p := verifiedPerson(t, st, "who@example.com")
	sess, ws, err := st.CreateWebSession(p.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.LookupWebSession(sess); err != nil || got.PersonID != p.ID || got.CSRF != ws.CSRF {
		t.Fatalf("session %+v %v", got, err)
	}
	st.DeleteWebSession(sess)
	if _, err := st.LookupWebSession(sess); !errors.Is(err, ErrNotFound) {
		t.Fatal("signed-out session still live")
	}

	h, _ := HashPassword("correct horse battery")
	if !CheckPassword(h, "correct horse battery") || CheckPassword(h, "wrong") || CheckPassword("garbage", "x") {
		t.Fatal("password check broken")
	}

	agent, _, err := st.CreateApprovedAgentForPerson(p, "claude")
	if err != nil {
		t.Fatal(err)
	}
	code, err := st.CreateOAuthCode(OAuthCode{ClientID: "c1", PersonID: p.ID, AgentID: agent.ID,
		RedirectURI: "https://claude.ai/api/mcp/auth_callback", CodeChallenge: "x", Resource: "https://example.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.ConsumeOAuthCode(code)
	if err != nil || c.AgentID != agent.ID {
		t.Fatalf("consume code %+v %v", c, err)
	}
	access, refresh, _, err := st.IssueOAuthTokens(OAuthToken{Family: c.Family, ClientID: c.ClientID,
		PersonID: p.ID, AgentID: agent.ID, Resource: c.Resource}, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tk, err := st.OAuthTokenByAccess(access); err != nil || tk.AgentID != agent.ID {
		t.Fatalf("access lookup %+v %v", tk, err)
	}
	// Replaying the code revokes the family it minted.
	if _, err := st.ConsumeOAuthCode(code); !errors.Is(err, ErrCodeReused) {
		t.Fatalf("code replay: %v", err)
	}
	if _, err := st.OAuthTokenByAccess(access); !errors.Is(err, ErrNotFound) {
		t.Fatal("tokens survived code replay")
	}
	// Fresh family: rotate, then replay the old refresh token.
	access, refresh, _, _ = st.IssueOAuthTokens(OAuthToken{Family: "fam2", ClientID: "c1",
		PersonID: p.ID, AgentID: agent.ID}, time.Hour, 24*time.Hour)
	a2, r2, _, err := st.RotateRefreshToken(refresh, time.Hour, 24*time.Hour)
	if err != nil || a2 == "" || r2 == refresh {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := st.OAuthTokenByAccess(access); !errors.Is(err, ErrNotFound) {
		t.Fatal("rotated-away access token still live")
	}
	if _, _, _, err := st.RotateRefreshToken(refresh, time.Hour, 24*time.Hour); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("refresh replay: %v", err)
	}
	if _, err := st.OAuthTokenByAccess(a2); !errors.Is(err, ErrNotFound) {
		t.Fatal("family survived refresh replay")
	}
	// Account deletion removes everything person-scoped.
	if err := st.DeletePerson(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AgentByID(agent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("agent survived account deletion")
	}
}

func TestAvailableHandle(t *testing.T) {
	st, _, _ := Open(t.TempDir(), "")
	defer st.Close()
	h1, _ := st.AvailableHandle("Jo")
	if h1 != "jox" {
		t.Fatalf("short handle padded to %q", h1)
	}
	verifiedPerson(t, st, "admin@example.com") // "admin" is reserved
	p2 := verifiedPerson(t, st, "admin@other.com")
	if strings.HasPrefix(p2.Handle, "admin") && p2.Handle == "admin" {
		t.Fatal("reserved handle allocated")
	}
	if _, err := st.CreateVerifiedPerson("admin@example.com", ""); err != nil {
		t.Fatal(err) // existing account returned, not an error
	}
}
