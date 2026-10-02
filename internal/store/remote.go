package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/s3"
)

// schemaRemoteBlobsV14 lets blob bytes live in an S3-compatible bucket (R2).
// A blob row maps a sha256 to the object holding its bytes; object keys are
// random per upload ("o/<hex>"), never the hash, so concurrent uploads of the
// same content never contend for one key and a half-written object can never
// masquerade as verified content. object_tombs makes object deletion
// crash-safe: a key is recorded in the same transaction that drops its blob
// row and removed only after the bucket delete succeeds.
const schemaRemoteBlobsV14 = `
ALTER TABLE blobs ADD COLUMN object_key TEXT NOT NULL DEFAULT '';
CREATE TABLE object_tombs (
  object_key TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
`

// ErrRemoteBlob is returned by OpenBlob when bytes live in a bucket rather
// than on local disk; callers stream with BlobReader or redirect to BlobURL.
var ErrRemoteBlob = errors.New("blob bytes are in remote object storage")

// remotePartSize is the multipart part size for server-side streaming into the
// bucket. R2 needs equal-sized parts (except the last), 5 MiB–5 GiB.
const remotePartSize = 16 << 20

// SetRemote moves blob bytes into an S3-compatible bucket. Existing local
// blobs are not migrated; a remote store expects a fresh data set.
func (s *Store) SetRemote(c *s3.Client) { s.remote = c }

// Remote reports whether blob bytes live in object storage.
func (s *Store) Remote() bool { return s.remote != nil }

// RemoteClient exposes the bucket client (upload sessions presign with it).
func (s *Store) RemoteClient() *s3.Client { return s.remote }

func newObjectKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "o/" + hex.EncodeToString(b)
}

// putRemoteBlob streams r into a fresh object while hashing it, then records
// (or deduplicates onto) the blob row. Bytes over limit fail with ErrQuota and
// leave nothing behind.
func (s *Store) putRemoteBlob(r io.Reader, limit int64) (string, int64, error) {
	ctx := context.Background()
	key := newObjectKey()
	h := sha256.New()
	lr := io.LimitReader(r, limit+1)
	buf := make([]byte, remotePartSize)

	n, err := io.ReadFull(lr, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", 0, err
	}
	var size int64
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// Small object: one PUT.
		size = int64(n)
		if size > limit {
			return "", 0, ErrQuota
		}
		h.Write(buf[:n])
		if _, err := s.remote.PutObject(ctx, key, bytes.NewReader(buf[:n]), size, ""); err != nil {
			return "", 0, fmt.Errorf("store object: %w", err)
		}
	} else {
		uploadID, err := s.remote.CreateMultipartUpload(ctx, key, "")
		if err != nil {
			return "", 0, fmt.Errorf("start multipart upload: %w", err)
		}
		abort := func() { _ = s.remote.AbortMultipartUpload(context.Background(), key, uploadID) }
		var parts []s3.Part
		for num := 1; ; num++ {
			size += int64(n)
			if size > limit {
				abort()
				return "", 0, ErrQuota
			}
			h.Write(buf[:n])
			etag, err := s.remote.UploadPart(ctx, key, uploadID, num, bytes.NewReader(buf[:n]), int64(n))
			if err != nil {
				abort()
				return "", 0, fmt.Errorf("upload part %d: %w", num, err)
			}
			parts = append(parts, s3.Part{Number: num, ETag: etag})
			n, err = io.ReadFull(lr, buf)
			if err == io.EOF {
				break
			}
			if err != nil && err != io.ErrUnexpectedEOF {
				abort()
				return "", 0, err
			}
			if err == io.ErrUnexpectedEOF {
				// Last, short part.
				size += int64(n)
				if size > limit {
					abort()
					return "", 0, ErrQuota
				}
				h.Write(buf[:n])
				etag, err := s.remote.UploadPart(ctx, key, uploadID, num+1, bytes.NewReader(buf[:n]), int64(n))
				if err != nil {
					abort()
					return "", 0, fmt.Errorf("upload part %d: %w", num+1, err)
				}
				parts = append(parts, s3.Part{Number: num + 1, ETag: etag})
				break
			}
		}
		if err := s.remote.CompleteMultipartUpload(ctx, key, uploadID, parts); err != nil {
			abort()
			return "", 0, fmt.Errorf("complete multipart upload: %w", err)
		}
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if err := s.RecordRemoteObject(sha, size, key); err != nil {
		_ = s.remote.DeleteObject(context.Background(), key)
		return "", 0, err
	}
	return sha, size, nil
}

// RecordRemoteObject attaches a verified object (bytes hashing to sha) to the
// blob table. If the content already exists, the new object is redundant and is
// deleted; the existing row's created_at is refreshed so the orphan GC grace
// window covers the caller until it takes its reference (AddFile/CreateLink).
func (s *Store) RecordRemoteObject(sha string, size int64, key string) error {
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	var existing string
	err := s.DB.QueryRow(`SELECT object_key FROM blobs WHERE sha256=?`, sha).Scan(&existing)
	switch {
	case err == nil && existing != "" && existing != key:
		if _, err := s.DB.Exec(`UPDATE blobs SET created_at=? WHERE sha256=?`, now(), sha); err != nil {
			return err
		}
		// Dedup: the bytes are already stored. Losing this delete only leaks an
		// unreferenced object; record it so the next GC retries.
		if derr := s.remote.DeleteObject(context.Background(), key); derr != nil {
			_, _ = s.DB.Exec(`INSERT OR IGNORE INTO object_tombs(object_key,created_at) VALUES(?,?)`, key, now())
		}
		return nil
	case err == nil:
		_, err = s.DB.Exec(`UPDATE blobs SET object_key=?, size=?, created_at=? WHERE sha256=?`, key, size, now(), sha)
		return err
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.DB.Exec(`INSERT INTO blobs(sha256,size,created_at,object_key) VALUES(?,?,?,?)`, sha, size, now(), key)
		return err
	default:
		return err
	}
}

func (s *Store) objectKey(sha string) (string, int64, error) {
	var key string
	var size int64
	err := s.DB.QueryRow(`SELECT object_key, size FROM blobs WHERE sha256=?`, sha).Scan(&key, &size)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && key == "") {
		return "", 0, ErrNotFound
	}
	return key, size, err
}

// BlobReader opens a blob's bytes for streaming in either storage mode.
func (s *Store) BlobReader(ctx context.Context, sha string) (io.ReadCloser, int64, error) {
	if s.remote == nil {
		f, err := s.OpenBlob(sha)
		if err != nil {
			return nil, 0, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		return f, info.Size(), nil
	}
	key, size, err := s.objectKey(sha)
	if err != nil {
		return nil, 0, err
	}
	body, _, err := s.remote.GetObject(ctx, key, "")
	if errors.Is(err, s3.ErrNotFound) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	return body, size, nil
}

// BlobURL returns a short-lived direct download URL for a remote blob, served
// as an attachment named name. In local mode it returns ErrNotFound — the
// caller streams instead.
func (s *Store) BlobURL(sha, name, mime string, ttl time.Duration) (string, error) {
	if s.remote == nil {
		return "", ErrNotFound
	}
	key, _, err := s.objectKey(sha)
	if err != nil {
		return "", err
	}
	return s.remote.PresignGet(key, ttl, contentDisposition(name), mime)
}

// contentDisposition builds an attachment header with an ASCII fallback and an
// RFC 5987 UTF-8 filename, so any folder name survives the round trip.
func contentDisposition(name string) string {
	ascii := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			c = '_'
		}
		ascii = append(ascii, c)
	}
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, ascii, rfc5987(name))
}

func rfc5987(s string) string {
	const hexd = "0123456789ABCDEF"
	out := make([]byte, 0, len(s)*3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			out = append(out, c)
			continue
		}
		out = append(out, '%', hexd[c>>4], hexd[c&15])
	}
	return string(out)
}

// deleteOrphanRemoteBlobs is DeleteOrphanBlobs for bucket mode. Each candidate
// row is rechecked and deleted in a transaction that also records its object
// key as a tomb; the bucket delete happens after commit and clears the tomb.
// A crash between the two leaves the tomb for the next run.
func (s *Store) deleteOrphanRemoteBlobs() (int, error) {
	grace := now() - 300
	rows, err := s.DB.Query(`SELECT sha256 FROM blobs WHERE created_at<=? AND NOT (`+blobReferencedSQL+`)`, grace)
	if err != nil {
		return 0, err
	}
	var shas []string
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			rows.Close()
			return 0, err
		}
		shas = append(shas, sha)
	}
	rows.Close()
	n := 0
	for _, sha := range shas {
		s.blobMu.Lock()
		err := func() error {
			tx, err := s.DB.Begin()
			if err != nil {
				return err
			}
			defer tx.Rollback()
			var key string
			err = tx.QueryRow(`SELECT object_key FROM blobs WHERE sha256=? AND created_at<=?
				AND NOT (`+blobReferencedSQL+`)`, sha, grace).Scan(&key)
			if errors.Is(err, sql.ErrNoRows) {
				return nil // gained a reference or was refreshed meanwhile
			}
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM blobs WHERE sha256=?`, sha); err != nil {
				return err
			}
			if key != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO object_tombs(object_key,created_at) VALUES(?,?)`, key, now()); err != nil {
					return err
				}
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			n++
			return nil
		}()
		s.blobMu.Unlock()
		if err != nil {
			return n, err
		}
	}
	return n, s.drainObjectTombs()
}

// drainObjectTombs deletes bucket objects whose blob rows are gone.
func (s *Store) drainObjectTombs() error {
	rows, err := s.DB.Query(`SELECT object_key FROM object_tombs ORDER BY created_at LIMIT 1000`)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	var firstErr error
	for _, k := range keys {
		// A tomb's key can never be live again: keys are random per upload and
		// a blob row is only ever pointed at a key by the upload that wrote it.
		if err := s.remote.DeleteObject(context.Background(), k); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := s.DB.Exec(`DELETE FROM object_tombs WHERE object_key=?`, k); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		log.Printf("store: object tomb cleanup: %v", firstErr)
	}
	return nil
}

// TombObject schedules an unreferenced bucket object for deletion (used for
// abandoned or rejected direct uploads).
func (s *Store) TombObject(key string) {
	if key == "" {
		return
	}
	_, _ = s.DB.Exec(`INSERT OR IGNORE INTO object_tombs(object_key,created_at) VALUES(?,?)`, key, now())
}
