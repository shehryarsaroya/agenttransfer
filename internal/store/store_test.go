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

func blobRefs(t *testing.T, s *Store, sha string) int64 {
	t.Helper()
	var n int64
	if err := s.DB.QueryRow(`SELECT refs FROM blobs WHERE sha256=?`, sha).Scan(&n); err != nil {
		t.Fatalf("refs(%s): %v", sha, err)
	}
	return n
}

func put(t *testing.T, s *Store, content string) (sha string, size int64) {
	t.Helper()
	sha, size, err := s.PutBlob(strings.NewReader(content), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return sha, size
}

// A link may be closed exactly once — a second close (burn racing revoke,
// janitor racing either) must not decrement the blob ref again. Regression
// test for the double-decrement data-loss bug.
func TestCloseLinkDecrementsOnce(t *testing.T) {
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
	if got := blobRefs(t, s, sha); got != 2 { // file row + link
		t.Fatalf("refs = %d, want 2", got)
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
	if got := blobRefs(t, s, sha); got != 1 { // the file row's ref survives
		t.Fatalf("refs after double close = %d, want 1 — the file's bytes would have been GC'd", got)
	}
}

// Duplicate DeleteFile calls decrement by what each call actually deleted.
func TestDeleteFileDecrementsByRowsDeleted(t *testing.T) {
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
	if got := blobRefs(t, s, sha); got != 2 {
		t.Fatalf("refs = %d, want 2", got)
	}
	if _, err := s.DeleteFile(a.ID, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteFile(a.ID, sha); err != ErrNotFound {
		t.Fatalf("second delete should be NotFound, got %v", err)
	}
	if got := blobRefs(t, s, sha); got != 1 {
		t.Fatalf("refs = %d, want 1 — bob's copy must survive alice's double delete", got)
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
