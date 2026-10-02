//go:build r2live

package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveR2 exercises the client against a real bucket:
//
//	S3_ENDPOINT=… S3_BUCKET=… S3_ACCESS_KEY_ID=… S3_SECRET_ACCESS_KEY=… go test -tags r2live ./internal/s3 -run TestLiveR2 -v
func TestLiveR2(t *testing.T) {
	c := &Client{Endpoint: os.Getenv("S3_ENDPOINT"), Bucket: os.Getenv("S3_BUCKET"),
		AccessKey: os.Getenv("S3_ACCESS_KEY_ID"), SecretKey: os.Getenv("S3_SECRET_ACCESS_KEY")}
	if c.Endpoint == "" {
		t.Skip("no S3_ENDPOINT")
	}
	ctx := context.Background()
	key := "livetest/" + time.Now().Format("150405.000")
	// Presigned single PUT, then a presigned GET with a download filename.
	put, err := c.PresignPut(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPut, put, strings.NewReader("hello r2"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("presigned put: %v %v %s", resp.StatusCode, err, b)
	}
	resp.Body.Close()
	get, _ := c.PresignGet(key, time.Minute, `attachment; filename="r.txt"; filename*=UTF-8''r%C3%A9.txt`, "text/plain")
	resp, err = http.Get(get)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned get: %v %v", resp.StatusCode, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("content-disposition: %q content-type: %q", resp.Header.Get("Content-Disposition"), resp.Header.Get("Content-Type"))
	if string(body) != "hello r2" {
		t.Fatalf("get body %q", body)
	}
	// Multipart with a 5 MiB part via presigned UploadPart, plus a tail.
	mkey := key + "-mp"
	id, err := c.CreateMultipartUpload(ctx, mkey, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	p1 := make([]byte, 5<<20)
	rand.Read(p1)
	u1, _ := c.PresignUploadPart(mkey, id, 1, time.Minute)
	req, _ = http.NewRequest(http.MethodPut, u1, bytes.NewReader(p1))
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned part: %v %v", resp.StatusCode, err)
	}
	e1 := resp.Header.Get("ETag")
	resp.Body.Close()
	e2, err := c.UploadPart(ctx, mkey, id, 2, strings.NewReader("tail"), 4)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := c.ListParts(ctx, mkey, id)
	if err != nil || len(parts) != 2 {
		t.Fatalf("list parts %v %v", parts, err)
	}
	if err := c.CompleteMultipartUpload(ctx, mkey, id, []Part{{1, e1}, {2, e2}}); err != nil {
		t.Fatal(err)
	}
	info, err := c.HeadObject(ctx, mkey)
	if err != nil || info.Size != int64(len(p1))+4 {
		t.Fatalf("head %+v %v", info, err)
	}
	rc, n, err := c.GetObject(ctx, mkey, "bytes=5242880-5242883")
	if err != nil {
		t.Fatal(err)
	}
	tail, _ := io.ReadAll(rc)
	rc.Close()
	if string(tail) != "tail" || n != 4 {
		t.Fatalf("range %q %d", tail, n)
	}
	for _, k := range []string{key, mkey} {
		if err := c.DeleteObject(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.HeadObject(ctx, key); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	// The scoped token must not reach another bucket.
	other := *c
	other.Bucket = "robotmodels-data"
	if _, err := other.HeadObject(ctx, "anything"); err == nil || err == ErrNotFound {
		t.Fatalf("scoped token reached another bucket: %v", err)
	} else {
		t.Logf("other bucket correctly refused: %v", err)
	}
}
