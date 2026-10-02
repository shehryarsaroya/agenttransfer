package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/s3/s3test"
	serverpkg "github.com/shehryarsaroya/agenttransfer/internal/server"
)

// TestUploadBodyGoesDirectToStorage runs the CLI uploader against a real
// server whose blobs live in a (fake) bucket: a small file takes the single
// presigned PUT, a larger one the parallel multipart path, an encrypting
// stream is spooled first — and every result round-trips byte for byte.
func TestUploadBodyGoesDirectToStorage(t *testing.T) {
	defer serverpkg.SetUploadThresholds(4<<10, 5<<10)()
	fake := s3test.New()
	bucket := httptest.NewServer(fake)
	defer bucket.Close()
	cfg := serverpkg.Config{DataDir: t.TempDir(), Metrics: "off",
		S3Endpoint: bucket.URL, S3Bucket: "b", S3AccessKey: "AK", S3SecretKey: "SK"}
	cfg.ApplyDefaults()
	srv, _, err := serverpkg.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.SetBaseURL(ts.URL)
	_, key, err := srv.Store().CreateAgent("cli-up", "", true)
	if err != nil {
		t.Fatal(err)
	}
	a := newAPI(clientConfig{URL: ts.URL, APIKey: key})
	if !a.directUploads() {
		t.Fatal("server did not advertise direct uploads")
	}
	dir := t.TempDir()
	for _, size := range []int{1 << 10, 23<<10 + 17} { // single PUT, then 5 parts
		data := make([]byte, size)
		rand.Read(data)
		path := filepath.Join(dir, "f.bin")
		os.WriteFile(path, data, 0o644)
		f, _ := os.Open(path)
		res, err := a.uploadBody("f.bin", f, true, "1h", false, io.Discard)
		f.Close()
		if err != nil {
			t.Fatalf("upload %d bytes: %v", size, err)
		}
		sum := sha256.Sum256(data)
		if res.SHA256 != hex.EncodeToString(sum[:]) || res.Size != int64(size) {
			t.Fatalf("result %+v", res)
		}
		// The bytes are fetchable through the authenticated redirect.
		req, _ := http.NewRequest("GET", ts.URL+"/v1/files/"+res.SHA256+"/content", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Equal(got, data) {
			t.Fatalf("round trip of %d bytes mismatched", size)
		}
	}
	// A non-file reader (e.g. an encrypting stream) is spooled, then uploaded.
	res, err := a.uploadBody("note.txt", strings.NewReader(strings.Repeat("x", 9000)), false, "", false, io.Discard)
	if err != nil || res.Size != 9000 {
		t.Fatalf("stream upload %+v %v", res, err)
	}
	// The same bytes again are recognized instantly (already in the folder).
	res2, err := a.uploadBody("again.txt", strings.NewReader(strings.Repeat("x", 9000)), false, "", false, io.Discard)
	if err != nil || res2.SHA256 != res.SHA256 {
		t.Fatalf("dedup upload %+v %v", res2, err)
	}
}
