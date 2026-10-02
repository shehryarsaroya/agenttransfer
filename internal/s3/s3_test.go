package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/s3/s3test"
)

// AWS's published Signature Version 4 examples for S3 (secret
// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY, 2013-05-24, us-east-1).
func awsExampleClient() *Client {
	return &Client{
		Region:    "us-east-1",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		now:       func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) },
	}
}

func TestSignatureGetObjectExample(t *testing.T) {
	c := awsExampleClient()
	u, _ := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	sig, signed := c.signature("GET", u, url.Values{}, map[string]string{
		"host":                 "examplebucket.s3.amazonaws.com",
		"range":                "bytes=0-9",
		"x-amz-content-sha256": emptySHA256,
		"x-amz-date":           "20130524T000000Z",
	}, emptySHA256, c.clock())
	if signed != "host;range;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("signed headers = %q", signed)
	}
	if want := "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"; sig != want {
		t.Fatalf("signature = %s, want %s", sig, want)
	}
}

func TestSignaturePresignedExample(t *testing.T) {
	c := awsExampleClient()
	u, _ := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	q := url.Values{
		"X-Amz-Algorithm":     {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":    {"AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {"20130524T000000Z"},
		"X-Amz-Expires":       {"86400"},
		"X-Amz-SignedHeaders": {"host"},
	}
	sig, _ := c.signature("GET", u, q, map[string]string{"host": "examplebucket.s3.amazonaws.com"}, unsignedPayload, c.clock())
	if want := "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"; sig != want {
		t.Fatalf("presigned signature = %s, want %s", sig, want)
	}
}

func TestURIEncode(t *testing.T) {
	if got := uriEncode("/test$file.text", false); got != "/test%24file.text" {
		t.Fatalf("got %q", got)
	}
	if got := uriEncode("a b/c~", true); got != "a%20b%2Fc~" {
		t.Fatalf("got %q", got)
	}
}

func TestPresignShape(t *testing.T) {
	c := &Client{Endpoint: "https://acct.r2.cloudflarestorage.com", Bucket: "bkt", AccessKey: "AK", SecretKey: "SK"}
	raw, err := c.PresignGet("o/abc def", 10*time.Minute, `attachment; filename="r.pdf"`, "application/pdf")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "acct.r2.cloudflarestorage.com" || u.EscapedPath() != "/bkt/o/abc%20def" {
		t.Fatalf("bad url %s", raw)
	}
	q := u.Query()
	for _, k := range []string{"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Date", "response-content-disposition"} {
		if q.Get(k) == "" {
			t.Fatalf("missing %s in %s", k, raw)
		}
	}
	if q.Get("X-Amz-Expires") != "600" || !strings.Contains(q.Get("X-Amz-Credential"), "/auto/s3/aws4_request") {
		t.Fatalf("bad expiry/credential in %s", raw)
	}
	if _, err := c.Presign("GET", "k", 30*24*time.Hour, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// TestOperationsAgainstFake drives every operation through the in-memory fake.
func TestOperationsAgainstFake(t *testing.T) {
	fake := s3test.New()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c := &Client{Endpoint: srv.URL, Bucket: "bkt", AccessKey: "AK", SecretKey: "SK", HTTP: srv.Client()}
	ctx := context.Background()

	if _, err := c.HeadObject(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("head missing: %v", err)
	}
	if _, err := c.PutObject(ctx, "a/b.txt", strings.NewReader("hello"), 5, "text/plain"); err != nil {
		t.Fatal(err)
	}
	info, err := c.HeadObject(ctx, "a/b.txt")
	if err != nil || info.Size != 5 {
		t.Fatalf("head: %+v %v", info, err)
	}
	body, n, err := c.GetObject(ctx, "a/b.txt", "bytes=1-3")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(body)
	body.Close()
	if string(got) != "ell" || n != 3 {
		t.Fatalf("range get = %q (%d)", got, n)
	}

	id, err := c.CreateMultipartUpload(ctx, "big", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	p1 := bytes.Repeat([]byte("x"), 10)
	e1, err := c.UploadPart(ctx, "big", id, 1, bytes.NewReader(p1), int64(len(p1)))
	if err != nil {
		t.Fatal(err)
	}
	// Part 2 goes through a presigned URL, as a client would upload it.
	purl, err := c.PresignUploadPart("big", id, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPut, purl, strings.NewReader("tail"))
	resp, err := srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned part: %v %v", resp, err)
	}
	e2 := resp.Header.Get("ETag")
	resp.Body.Close()
	parts, err := c.ListParts(ctx, "big", id)
	if err != nil || len(parts) != 2 {
		t.Fatalf("list parts: %+v %v", parts, err)
	}
	if err := c.CompleteMultipartUpload(ctx, "big", id, []Part{{2, e2}, {1, e1}}); err != nil {
		t.Fatal(err)
	}
	body, _, err = c.GetObject(ctx, "big", "")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(body)
	body.Close()
	if string(got) != "xxxxxxxxxxtail" {
		t.Fatalf("assembled = %q", got)
	}

	// Presigned PUT then presigned GET.
	put, _ := c.PresignPut("p", time.Hour)
	req, _ = http.NewRequest(http.MethodPut, put, strings.NewReader("direct"))
	resp, err = srv.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned put: %v %v", resp, err)
	}
	resp.Body.Close()
	get, _ := c.PresignGet("p", time.Minute, `attachment; filename="p.bin"`, "")
	resp, err = srv.Client().Get(get)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned get: %v %v", resp, err)
	}
	got, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "direct" || !strings.Contains(resp.Header.Get("Content-Disposition"), "p.bin") {
		t.Fatalf("presigned get body=%q cd=%q", got, resp.Header.Get("Content-Disposition"))
	}

	if err := c.DeleteObject(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HeadObject(ctx, "p"); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	id2, _ := c.CreateMultipartUpload(ctx, "gone", "")
	if err := c.AbortMultipartUpload(ctx, "gone", id2); err != nil {
		t.Fatal(err)
	}
	if fake.Objects() != 2 {
		t.Fatalf("objects = %d, want 2", fake.Objects())
	}
}
