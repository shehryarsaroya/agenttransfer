package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
)

type env struct {
	t      *testing.T
	ts     *httptest.Server
	srv    *Server
	admin  string
	client *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := Config{DataDir: t.TempDir(), Metrics: "off"}
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.SetBaseURL(ts.URL)
	return &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}
}

func (e *env) do(method, path, key string, body io.Reader, contentType string, headers ...string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, data
}

func (e *env) doJSON(method, path, key string, in any, out any, headers ...string) int {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		buf, _ := json.Marshal(in)
		body = bytes.NewReader(buf)
	}
	resp, data := e.do(method, path, key, body, "application/json", headers...)
	if out != nil && len(data) > 0 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			e.t.Fatalf("%s %s: bad JSON %q: %v", method, path, data, err)
		}
	}
	return resp.StatusCode
}

func (e *env) createAgent(name string) (email, key string) {
	e.t.Helper()
	var out struct {
		Email  string `json:"email"`
		APIKey string `json:"api_key"`
	}
	code := e.doJSON("POST", "/v1/agents", e.admin, map[string]string{"name": name}, &out)
	if code != 201 {
		e.t.Fatalf("create agent %s: HTTP %d", name, code)
	}
	return out.Email, out.APIKey
}

func (e *env) upload(key, name string, data []byte, query string) map[string]any {
	e.t.Helper()
	resp, body := e.do("PUT", "/v1/files/"+name+query, key, bytes.NewReader(data), "application/octet-stream")
	if resp.StatusCode != 201 {
		e.t.Fatalf("upload %s: HTTP %d %s", name, resp.StatusCode, body)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return out
}

func TestFullHandoffFlow(t *testing.T) {
	e := newEnv(t)
	_, aliceKey := e.createAgent("alice")
	bobEmail, bobKey := e.createAgent("bob")

	payload := make([]byte, 256*1024)
	rand.Read(payload)
	wantSHA := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantSHA[:])

	up := e.upload(aliceKey, "weights.bin", payload, "")
	if up["sha256"] != wantHex {
		t.Fatalf("sha mismatch: %v != %s", up["sha256"], wantHex)
	}

	// Send with idempotency.
	send := map[string]any{"to": []string{bobEmail}, "file": "sha256:" + wantHex, "note": "v3"}
	var sent struct {
		MessageID string `json:"message_id"`
		Link      struct {
			URL string `json:"url"`
		} `json:"link"`
		Delivered []map[string]any `json:"delivered"`
	}
	code := e.doJSON("POST", "/v1/send", aliceKey, send, &sent, "Idempotency-Key", "k1")
	if code != 201 || len(sent.Delivered) != 1 {
		t.Fatalf("send: HTTP %d %+v", code, sent)
	}

	// Replay returns the same message id, no second delivery.
	var replay struct {
		MessageID string `json:"message_id"`
	}
	code = e.doJSON("POST", "/v1/send", aliceKey, send, &replay, "Idempotency-Key", "k1")
	if code != 200 || replay.MessageID != sent.MessageID {
		t.Fatalf("idempotent replay failed: HTTP %d %q vs %q", code, replay.MessageID, sent.MessageID)
	}

	// Bob's inbox has exactly one message with a trusted offer.
	var inbox struct {
		Messages []struct {
			ID    string `json:"id"`
			Offer struct {
				URL     string `json:"url"`
				SHA256  string `json:"sha256"`
				Trusted bool   `json:"trusted"`
			} `json:"offer"`
		} `json:"messages"`
	}
	e.doJSON("GET", "/v1/inbox?unread=1", bobKey, nil, &inbox)
	if len(inbox.Messages) != 1 {
		t.Fatalf("bob inbox: %d messages", len(inbox.Messages))
	}
	offer := inbox.Messages[0].Offer
	if offer.SHA256 != wantHex || !offer.Trusted {
		t.Fatalf("offer wrong: %+v", offer)
	}

	// Download via the public link; verify bytes.
	resp, data := e.do("GET", strings.TrimPrefix(offer.URL, e.ts.URL)+"?dl=1", "", nil, "")
	if resp.StatusCode != 200 || !bytes.Equal(data, payload) {
		t.Fatalf("download failed: HTTP %d, %d bytes", resp.StatusCode, len(data))
	}
	if resp.Header.Get("X-Sha256") != wantHex {
		t.Fatalf("X-Sha256 header missing/wrong")
	}

	// Reply threading.
	var reply struct {
		MessageID string `json:"message_id"`
		Subject   string `json:"subject"`
	}
	e.doJSON("POST", "/v1/send", bobKey, map[string]any{
		"to": []string{"alice@local"}, "note": "got it, hashes match", "reply_to": inbox.Messages[0].ID,
	}, &reply)
	var aliceInbox struct {
		Messages []struct {
			InReplyTo string `json:"in_reply_to"`
			Subject   string `json:"subject"`
		} `json:"messages"`
	}
	e.doJSON("GET", "/v1/inbox?unread=1", aliceKey, nil, &aliceInbox)
	if len(aliceInbox.Messages) != 1 {
		t.Fatalf("alice inbox: %d", len(aliceInbox.Messages))
	}
	if aliceInbox.Messages[0].InReplyTo == "" || !strings.HasPrefix(aliceInbox.Messages[0].Subject, "Re:") {
		t.Fatalf("threading broken: %+v", aliceInbox.Messages[0])
	}

	// Receipts: full export must chain-verify.
	var wk struct {
		ReceiptPubkey string `json:"receipt_pubkey"`
	}
	e.doJSON("GET", "/.well-known/agenttransfer", "", nil, &wk)
	pub, err := receipt.ParsePublicKey(wk.ReceiptPubkey)
	if err != nil {
		t.Fatal(err)
	}
	resp, data = e.do("GET", "/v1/receipts/export", e.admin, nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("export: HTTP %d", resp.StatusCode)
	}
	rs, err := receipt.ReadJSONL(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	// The export is already in chain order — verify as-is, never re-sorted.
	if err := receipt.VerifyChain(rs, pub, true); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if len(rs) < 5 {
		t.Fatalf("expected a busy receipt chain, got %d", len(rs))
	}
}

func TestLongPollDelivers(t *testing.T) {
	e := newEnv(t)
	_, aliceKey := e.createAgent("alice")
	bobEmail, bobKey := e.createAgent("bob")

	done := make(chan []byte, 1)
	go func() {
		_, data := e.do("GET", "/v1/inbox/wait?timeout=15", bobKey, nil, "")
		done <- data
	}()
	time.Sleep(300 * time.Millisecond) // let the poll park

	e.doJSON("POST", "/v1/send", aliceKey, map[string]any{"to": []string{bobEmail}, "note": "ping"}, nil)

	select {
	case data := <-done:
		if !strings.Contains(string(data), "ping") {
			t.Fatalf("long poll returned wrong payload: %s", data)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long poll never woke up")
	}
}

func TestBurnAfterRead(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	payload := []byte("secret credentials")
	up := e.upload(key, "creds.txt", payload, "?once=1&ttl=1h")
	link, ok := up["link"].(map[string]any)
	if !ok {
		t.Fatalf("no link in upload response: %v", up)
	}
	path := strings.TrimPrefix(link["url"].(string), e.ts.URL)

	// The HTML page never burns.
	resp, body := e.do("GET", path, "", nil, "", "Accept", "text/html")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Single-download") {
		t.Fatalf("share page: HTTP %d", resp.StatusCode)
	}
	// HEAD never burns.
	resp, _ = e.do("HEAD", path, "", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD: %d", resp.StatusCode)
	}

	// First real download succeeds…
	resp, data := e.do("GET", path+"?dl=1", "", nil, "")
	if resp.StatusCode != 200 || !bytes.Equal(data, payload) {
		t.Fatalf("first download: HTTP %d", resp.StatusCode)
	}
	// …second gets 410 Gone.
	resp, _ = e.do("GET", path+"?dl=1", "", nil, "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("second download: HTTP %d, want 410", resp.StatusCode)
	}

	// ?once=true (like ?once=1) implies share: a link must be minted.
	up = e.upload(key, "creds2.txt", payload, "?once=true")
	link, ok = up["link"].(map[string]any)
	if !ok {
		t.Fatalf("once=true minted no link: %v", up)
	}
	if link["once"] != true {
		t.Fatalf("once=true link is not burn-after-read: %v", link)
	}
}

func TestRevokeKillsLink(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	up := e.upload(key, "x.bin", []byte("data"), "?share=1")
	link := up["link"].(map[string]any)
	token := link["token"].(string)
	path := strings.TrimPrefix(link["url"].(string), e.ts.URL)

	resp, _ := e.do("GET", path+"?dl=1", "", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("pre-revoke download: %d", resp.StatusCode)
	}
	code := e.doJSON("DELETE", "/v1/links/"+token, key, nil, nil)
	if code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	resp, _ = e.do("GET", path+"?dl=1", "", nil, "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("post-revoke download: HTTP %d, want 410", resp.StatusCode)
	}
}

func TestQuotaAndDedup(t *testing.T) {
	// ApplyDefaults must keep the explicit 1 KiB quota (the test fails loudly
	// at the 20 GB default if it doesn't).
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", StorageQuota: 1024, MaxFileSize: 4096}
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.SetBaseURL(ts.URL)
	e := &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}

	_, key := e.createAgent("alice")
	e.upload(key, "a.bin", bytes.Repeat([]byte("x"), 800), "")

	// Second upload exceeds the 1 KiB quota → 413.
	resp, _ := e.do("PUT", "/v1/files/b.bin", key, bytes.NewReader(bytes.Repeat([]byte("y"), 800)), "application/octet-stream")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("quota not enforced: HTTP %d", resp.StatusCode)
	}

	// Re-uploading identical content dedups (same sha, no quota change).
	up := e.upload(key, "a.bin", bytes.Repeat([]byte("x"), 800), "")
	var files struct {
		Files       []map[string]any `json:"files"`
		StorageUsed int64            `json:"storage_used"`
	}
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 1 || files.StorageUsed != 800 {
		t.Fatalf("dedup failed: %d files, %d used (%v)", len(files.Files), files.StorageUsed, up)
	}
}

func TestUnclaimedExpiry(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")

	// Create an upload request and drop a file through it (arrives unclaimed).
	var reqOut struct {
		UploadURL string `json:"upload_url"`
		Token     string `json:"token"`
	}
	e.doJSON("POST", "/v1/requests", key, map[string]any{"note": "drop it"}, &reqOut)

	var mp bytes.Buffer
	w := multipart.NewWriter(&mp)
	fw, _ := w.CreateFormFile("file", "video.mov")
	fw.Write([]byte("recording bytes"))
	w.Close()
	resp, body := e.do("POST", strings.TrimPrefix(reqOut.UploadURL, e.ts.URL), "", &mp, w.FormDataContentType())
	if resp.StatusCode != 200 {
		t.Fatalf("human upload: HTTP %d %s", resp.StatusCode, body)
	}

	// Second use of the one-time page must fail.
	var mp2 bytes.Buffer
	w2 := multipart.NewWriter(&mp2)
	fw2, _ := w2.CreateFormFile("file", "again.txt")
	fw2.Write([]byte("nope"))
	w2.Close()
	resp, _ = e.do("POST", strings.TrimPrefix(reqOut.UploadURL, e.ts.URL), "", &mp2, w2.FormDataContentType())
	if resp.StatusCode == 200 {
		t.Fatalf("one-time upload page worked twice")
	}

	// The file is in the folder, unclaimed.
	var files struct {
		Files []struct {
			SHA256  string `json:"sha256"`
			Claimed bool   `json:"claimed"`
		} `json:"files"`
	}
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 1 || files.Files[0].Claimed {
		t.Fatalf("expected one unclaimed file: %+v", files.Files)
	}
	sha := files.Files[0].SHA256

	// Expire it by force: age the file AND the blob past the GC grace
	// period, then run the janitor.
	if _, err := e.srv.Store().DB.Exec(`UPDATE files SET expires_at=1 WHERE claimed=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store().DB.Exec(`UPDATE blobs SET created_at=1`); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.JanitorOnce(); err != nil {
		t.Fatal(err)
	}
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 0 {
		t.Fatalf("unclaimed file survived the janitor: %+v", files.Files)
	}
	if _, err := e.srv.Store().OpenBlob(sha); err == nil {
		t.Fatalf("orphan blob survived GC")
	}

	// Keep-flow: a kept file must NOT expire.
	e.doJSON("POST", "/v1/requests", key, map[string]any{"note": "again"}, &reqOut)
	var mp3 bytes.Buffer
	w3 := multipart.NewWriter(&mp3)
	fw3, _ := w3.CreateFormFile("file", "keepme.txt")
	fw3.Write([]byte("keep these bytes"))
	w3.Close()
	e.do("POST", strings.TrimPrefix(reqOut.UploadURL, e.ts.URL), "", &mp3, w3.FormDataContentType())
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 1 {
		t.Fatalf("expected the new drop")
	}
	code := e.doJSON("POST", "/v1/files/"+files.Files[0].SHA256+"/keep", key, map[string]any{}, nil)
	if code != 200 {
		t.Fatalf("keep: %d", code)
	}
	e.srv.Store().DB.Exec(`UPDATE files SET expires_at=1 WHERE claimed=0`)
	e.srv.JanitorOnce()
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 1 || !files.Files[0].Claimed {
		t.Fatalf("kept file was lost: %+v", files.Files)
	}
}

func TestAuthAndSignupGates(t *testing.T) {
	e := newEnv(t)
	// No key → 401.
	resp, _ := e.do("GET", "/v1/files", "", nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated: %d", resp.StatusCode)
	}
	// Bad key → 401.
	resp, _ = e.do("GET", "/v1/files", "at_live_bogus", nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("bad key: %d", resp.StatusCode)
	}
	// Signup without admin on a gated instance → 403.
	code := e.doJSON("POST", "/v1/agents", "", map[string]string{"name": "mallory"}, nil)
	if code != 403 {
		t.Fatalf("gated signup: %d", code)
	}
	// Rotate key: old key dies.
	_, key := e.createAgent("alice")
	var rot struct {
		APIKey string `json:"api_key"`
	}
	e.doJSON("POST", "/v1/agents/self/rotate_key", key, map[string]any{}, &rot)
	resp, _ = e.do("GET", "/v1/files", key, nil, "")
	if resp.StatusCode != 401 {
		t.Fatalf("old key still alive: %d", resp.StatusCode)
	}
	resp, _ = e.do("GET", "/v1/files", rot.APIKey, nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("new key rejected: %d", resp.StatusCode)
	}
}

func TestOpenSignupRequiresVerification(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", OpenSignup: true}
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.SetBaseURL(ts.URL)
	e := &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}

	// Open signup needs owner_email.
	code := e.doJSON("POST", "/v1/agents", "", map[string]string{"name": "wanderer"}, nil)
	if code != 400 {
		t.Fatalf("signup without owner_email: %d", code)
	}
	var out struct {
		AgentID       string `json:"agent_id"`
		APIKey        string `json:"api_key"`
		OwnerVerified bool   `json:"owner_verified"`
	}
	code = e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "owner_email": "human@example.com"}, &out)
	if code != 201 || out.OwnerVerified {
		t.Fatalf("open signup: %d verified=%v", code, out.OwnerVerified)
	}
	// Local sends work unverified…
	e.createAgent("bob")
	code = e.doJSON("POST", "/v1/send", out.APIKey, map[string]any{"to": []string{"bob@local"}, "note": "hi"}, nil)
	if code != 201 {
		t.Fatalf("local send should work unverified: %d", code)
	}
	// …but admin verify endpoint flips the flag.
	code = e.doJSON("POST", "/v1/agents/"+out.AgentID+"/verify", e.admin, map[string]any{}, nil)
	if code != 200 {
		t.Fatalf("admin verify: %d", code)
	}
}

func TestMCPToolFlow(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	bobEmail, bobKey := e.createAgent("bob")

	rpc := func(method string, params any) map[string]any {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		resp, data := e.do("POST", "/mcp", key, bytes.NewReader(body), "application/json")
		if resp.StatusCode != 200 {
			t.Fatalf("mcp %s: HTTP %d %s", method, resp.StatusCode, data)
		}
		var out map[string]any
		_ = json.Unmarshal(data, &out)
		if out["error"] != nil {
			t.Fatalf("mcp %s: %v", method, out["error"])
		}
		res, _ := out["result"].(map[string]any)
		return res
	}

	init := rpc("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}})
	if init["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %v", init)
	}
	tools := rpc("tools/list", map[string]any{})
	if list, _ := tools["tools"].([]any); len(list) < 8 {
		t.Fatalf("tools/list: %v", tools)
	}

	call := func(name string, args any) string {
		res := rpc("tools/call", map[string]any{"name": name, "arguments": args})
		if res["isError"] == true {
			t.Fatalf("tool %s errored: %v", name, res)
		}
		content := res["content"].([]any)[0].(map[string]any)
		return content["text"].(string)
	}

	up := call("upload_file", map[string]any{"name": "notes.txt", "content_text": "hello from mcp", "share": true})
	if !strings.Contains(up, "sha256") {
		t.Fatalf("upload_file: %s", up)
	}
	sent := call("send", map[string]any{"to": []string{bobEmail}, "file": "notes.txt", "note": "over mcp"})
	if !strings.Contains(sent, "inbox") {
		t.Fatalf("send: %s", sent)
	}

	// Bob sees it via REST.
	var inbox struct {
		Messages []map[string]any `json:"messages"`
	}
	e.doJSON("GET", "/v1/inbox?unread=1", bobKey, nil, &inbox)
	if len(inbox.Messages) != 1 {
		t.Fatalf("bob inbox after mcp send: %d", len(inbox.Messages))
	}

	// Unauthenticated MCP is rejected.
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	resp, _ := e.do("POST", "/mcp", "", bytes.NewReader(body), "application/json")
	if resp.StatusCode != 401 {
		t.Fatalf("mcp unauthenticated: %d", resp.StatusCode)
	}
}

func TestSendValidation(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	// Empty send.
	code := e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"bob@local"}}, nil)
	if code != 400 {
		t.Fatalf("empty send: %d", code)
	}
	// Unknown local recipient.
	code = e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"ghost@local"}, "note": "hi"}, nil)
	if code != 400 {
		t.Fatalf("unknown recipient: %d", code)
	}
	// Remote recipient on a local-mode instance.
	code = e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"someone@example.com"}, "note": "hi"}, nil)
	if code != 400 {
		t.Fatalf("remote send in local mode: %d", code)
	}
	// Missing file.
	code = e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"alice@local"}, "file": "sha256:" + strings.Repeat("0", 64)}, nil)
	if code != 404 {
		t.Fatalf("missing file: %d", code)
	}
	// Recipients with only empty entries.
	code = e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"", "  "}, "note": "hi"}, nil)
	if code != 400 {
		t.Fatalf("empty recipients: %d", code)
	}
	// A rejected send must not have consumed send quota.
	var n int64
	if err := e.srv.Store().DB.QueryRow(`SELECT COALESCE(SUM(n),0) FROM counters WHERE kind='sends'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rejected sends consumed %d quota units", n)
	}
	// Duplicate recipients collapse to one delivery.
	_, bobKey := e.createAgent("bob")
	var sent struct {
		Delivered []map[string]any `json:"delivered"`
	}
	code = e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"bob@local", "BOB@local", " bob@local "}, "note": "hi"}, &sent)
	if code != 201 || len(sent.Delivered) != 1 {
		t.Fatalf("duplicate recipients: HTTP %d, %d deliveries", code, len(sent.Delivered))
	}
	var bobInbox struct {
		Messages []map[string]any `json:"messages"`
	}
	e.doJSON("GET", "/v1/inbox", bobKey, nil, &bobInbox)
	if len(bobInbox.Messages) != 1 {
		t.Fatalf("duplicate recipients delivered %d inbox copies", len(bobInbox.Messages))
	}
}

func TestCCOwnerRequiresVerifiedOwner(t *testing.T) {
	// Email-capable instance (Domain + Outbound set). The CC path must be
	// skipped before any relay dial; the relay points at a dead local port so
	// anything that does try to dial (signup's verification mail) fails fast
	// instead of touching the network.
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", OpenSignup: true,
		Domain: "agents.test", Outbound: "smtp://127.0.0.1:1"}
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.SetBaseURL(ts.URL)
	e := &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}

	var out struct {
		APIKey string `json:"api_key"`
	}
	code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "owner_email": "victim@example.com"}, &out)
	if code != 201 {
		t.Fatalf("open signup: %d", code)
	}
	_, _ = e.createAgent("bob")

	// Local send with cc_owner: delivered locally, CC skipped (not verified).
	var sent struct {
		Delivered []map[string]any `json:"delivered"`
		CCOwner   string           `json:"cc_owner"`
	}
	code = e.doJSON("POST", "/v1/send", out.APIKey,
		map[string]any{"to": []string{"bob@agents.test"}, "note": "hi", "cc_owner": true}, &sent)
	if code != 201 || len(sent.Delivered) != 1 {
		t.Fatalf("local send: HTTP %d %+v", code, sent)
	}
	if sent.CCOwner != "skipped (owner not verified)" {
		t.Fatalf("unverified cc_owner must be skipped, got %q", sent.CCOwner)
	}

	// Remote send by the unverified agent is still refused outright.
	code = e.doJSON("POST", "/v1/send", out.APIKey,
		map[string]any{"to": []string{"someone@elsewhere.test"}, "note": "hi"}, nil)
	if code != 403 {
		t.Fatalf("unverified remote send: HTTP %d, want 403", code)
	}
}

func TestWellKnownAndHealth(t *testing.T) {
	e := newEnv(t)
	var wk map[string]any
	code := e.doJSON("GET", "/.well-known/agenttransfer", "", nil, &wk)
	if code != 200 || wk["receipt_pubkey"] == "" || wk["name"] != "agenttransfer" {
		t.Fatalf("well-known: %d %v", code, wk)
	}
	resp, body := e.do("GET", "/healthz", "", nil, "")
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
}
