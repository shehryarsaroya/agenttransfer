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
	"github.com/shehryarsaroya/agenttransfer/internal/seal"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// testRecipient mints a valid age recipient ("age1...") for pubkey tests.
func testRecipient(t *testing.T) string {
	t.Helper()
	id, err := seal.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient()
}

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

func TestLaunchPageServesEmbeddedArtwork(t *testing.T) {
	e := newEnvCfg(t, Config{AppDomain: testAppDomain, BehindProxy: true})
	resp, body := e.do(http.MethodGet, "/launch", "", nil, "")
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("agent-hosting-hero.webp")) {
		t.Fatalf("launch page: HTTP %d body=%q", resp.StatusCode, body)
	}
	for _, name := range []string{"agent-hosting-hero.webp", "agent-hosting-detail.webp"} {
		resp, body = e.do(http.MethodGet, "/static/launch/"+name, "", nil, "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/webp" || len(body) < 1024 || !bytes.HasPrefix(body, []byte("RIFF")) {
			t.Fatalf("launch asset %s: HTTP %d type=%q bytes=%d", name, resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
		}
		if got := resp.Header.Get("Cache-Control"); got != "public, max-age=3600" {
			t.Fatalf("launch asset %s cache=%q", name, got)
		}
	}
	resp, body = e.do(http.MethodGet, "/static/launch/agent-hosting-hero.jpg", "", nil, "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/jpeg" || len(body) < 1024 || !bytes.HasPrefix(body, []byte{0xff, 0xd8}) {
		t.Fatalf("launch social image: HTTP %d type=%q bytes=%d", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	}
	resp, _ = e.do(http.MethodGet, "/static/launch/not-embedded.webp", "", nil, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown launch asset: HTTP %d", resp.StatusCode)
	}
	disabled := newEnv(t)
	resp, _ = disabled.do(http.MethodGet, "/launch", "", nil, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("static-only launch page: HTTP %d, want 404", resp.StatusCode)
	}
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
	replayRequest, _ := json.Marshal(send)
	replayResp, replayRaw := e.do("POST", "/v1/send", aliceKey, bytes.NewReader(replayRequest), "application/json", "Idempotency-Key", "k1")
	if replayResp.StatusCode != http.StatusOK || replayResp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("idempotent replay headers/status: HTTP %d Cache-Control=%q body=%s",
			replayResp.StatusCode, replayResp.Header.Get("Cache-Control"), replayRaw)
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
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("receipt export Cache-Control = %q, want no-store", got)
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

	// Keyed signup: no owner_email needed — a keyed agent is first-class and
	// ready to work with no human in the loop.
	var keyed struct {
		APIKey       string `json:"api_key"`
		Pubkey       string `json:"pubkey"`
		OwnerEmail   string `json:"owner_email"`
		Verification string `json:"verification"`
	}
	code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "pubkey": testRecipient(t)}, &keyed)
	if code != 201 {
		t.Fatalf("keyed signup (no owner_email): %d", code)
	}
	if keyed.Verification != "not_required" || keyed.OwnerEmail != "" || keyed.Pubkey == "" {
		t.Fatalf("keyed agent: verification=%q owner=%q pubkey=%q", keyed.Verification, keyed.OwnerEmail, keyed.Pubkey)
	}
	// It works same-instance immediately.
	e.createAgent("bob")
	if code := e.doJSON("POST", "/v1/send", keyed.APIKey, map[string]any{"to": []string{"bob@local"}, "note": "hi"}, nil); code != 201 {
		t.Fatalf("keyed agent local send should work: %d", code)
	}

	// Owned signup: owner_email given → unverified until confirmed; the admin
	// verify endpoint flips the flag (unlocking the outbound email projection).
	var owned struct {
		AgentID       string `json:"agent_id"`
		OwnerVerified bool   `json:"owner_verified"`
	}
	code = e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "settler", "owner_email": "human@example.com"}, &owned)
	if code != 201 || owned.OwnerVerified {
		t.Fatalf("owned signup: %d verified=%v", code, owned.OwnerVerified)
	}
	if code := e.doJSON("POST", "/v1/agents/"+owned.AgentID+"/verify", e.admin, map[string]any{}, nil); code != 200 {
		t.Fatalf("admin verify: %d", code)
	}
}

// Discovery: an agent publishes an opt-in card and another finds it by
// capability. Unlisted agents stay invisible (anti-enumeration preserved).
func TestDiscovery(t *testing.T) {
	e := newEnv(t)
	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")

	var card store.Card
	code := e.doJSON("PUT", "/v1/agents/self/card", aliceKey, map[string]any{
		"description":  "transcodes audio",
		"capabilities": []string{"Transcode", "audio", "transcode"}, // dupe + case
		"listed":       true,
	}, &card)
	if code != 200 {
		t.Fatalf("set card: %d", code)
	}
	if !card.Listed || len(card.Capabilities) != 2 { // normalized + deduped
		t.Fatalf("card not normalized: %+v", card)
	}

	var dir struct {
		Agents []store.Card `json:"agents"`
		Count  int          `json:"count"`
	}
	code = e.doJSON("GET", "/v1/directory?capability=transcode", bobKey, nil, &dir)
	if code != 200 || dir.Count != 1 || dir.Agents[0].Name != "alice" {
		t.Fatalf("directory by capability: %d %+v", code, dir)
	}
	if code = e.doJSON("GET", "/v1/directory?capability=nope", bobKey, nil, &dir); code != 200 || dir.Count != 0 {
		t.Fatalf("empty capability filter: %d count=%d", code, dir.Count)
	}

	// Bob published nothing → his card 404s and he's absent from the directory.
	if c, _ := e.do("GET", "/v1/agents/bob/card", aliceKey, nil, ""); c.StatusCode != 404 {
		t.Fatalf("bob has no card: want 404 got %d", c.StatusCode)
	}
	// Alice is fetchable by name while listed.
	if code = e.doJSON("GET", "/v1/agents/alice/card", bobKey, nil, &card); code != 200 || card.Description != "transcodes audio" {
		t.Fatalf("get alice card: %d %+v", code, card)
	}
	// Unlisting hides her again.
	e.doJSON("PUT", "/v1/agents/self/card", aliceKey, map[string]any{"description": "x", "listed": false}, nil)
	if c, _ := e.do("GET", "/v1/agents/alice/card", bobKey, nil, ""); c.StatusCode != 404 {
		t.Fatalf("unlisted alice: want 404 got %d", c.StatusCode)
	}
	if code = e.doJSON("GET", "/v1/directory", bobKey, nil, &dir); code != 200 || dir.Count != 0 {
		t.Fatalf("directory after unlist: count=%d", dir.Count)
	}
}

// Recipient accept policy: an agent controls who reaches its main inbox.
// "known" quarantines strangers (allowlisted or space co-members pass);
// "closed" refuses strangers outright; "open" (default) lets everyone through.
func TestAcceptPolicyQuarantine(t *testing.T) {
	e := newEnv(t)
	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")

	type delivery struct {
		Delivered []map[string]any `json:"delivered"`
	}
	type inbox struct {
		Messages []map[string]any `json:"messages"`
	}

	// Alice → "known": an unknown sender is quarantined, not dropped, not shown.
	if code := e.doJSON("PUT", "/v1/agents/self/policy", aliceKey, map[string]any{"accept": "known"}, nil); code != 200 {
		t.Fatalf("set policy: %d", code)
	}
	var sent delivery
	e.doJSON("POST", "/v1/send", bobKey, map[string]any{"to": []string{"alice@local"}, "note": "hi"}, &sent)
	if len(sent.Delivered) != 1 || sent.Delivered[0]["via"] != "quarantined" {
		t.Fatalf("unknown bob→alice via = %+v, want quarantined", sent.Delivered)
	}
	var main, quar inbox
	e.doJSON("GET", "/v1/inbox", aliceKey, nil, &main)
	e.doJSON("GET", "/v1/inbox?quarantined=1", aliceKey, nil, &quar)
	if len(main.Messages) != 0 || len(quar.Messages) != 1 || quar.Messages[0]["quarantined"] != true {
		t.Fatalf("main=%d quar=%d (want 0/1)", len(main.Messages), len(quar.Messages))
	}

	// Allowlisting bob promotes him to the main inbox.
	e.doJSON("PUT", "/v1/agents/self/policy", aliceKey, map[string]any{"accept": "known", "allow": []string{"bob@local"}}, nil)
	e.doJSON("POST", "/v1/send", bobKey, map[string]any{"to": []string{"alice@local"}, "note": "again"}, nil)
	e.doJSON("GET", "/v1/inbox", aliceKey, nil, &main)
	if len(main.Messages) != 1 {
		t.Fatalf("allowlisted bob should reach main inbox, got %d", len(main.Messages))
	}

	// A space co-member is "known" without any allowlist entry.
	_, eveKey := e.createAgent("eve")
	_, frankKey := e.createAgent("frank")
	e.doJSON("PUT", "/v1/agents/self/policy", eveKey, map[string]any{"accept": "known"}, nil)
	var sp struct {
		Space store.Space `json:"space"`
	}
	e.doJSON("POST", "/v1/spaces", eveKey, map[string]any{"name": "crew"}, &sp)
	e.doJSON("POST", "/v1/spaces/"+sp.Space.ID+"/members", eveKey, map[string]any{"agent": "frank@local"}, nil)
	e.doJSON("POST", "/v1/send", frankKey, map[string]any{"to": []string{"eve@local"}, "note": "teammate"}, nil)
	var emain inbox
	e.doJSON("GET", "/v1/inbox", eveKey, nil, &emain)
	if len(emain.Messages) != 1 {
		t.Fatalf("space co-member frank should reach eve's main inbox, got %d", len(emain.Messages))
	}

	// "closed": an unknown sender is refused outright (no message stored).
	_, daveKey := e.createAgent("dave")
	e.doJSON("PUT", "/v1/agents/self/policy", daveKey, map[string]any{"accept": "closed"}, nil)
	var rej delivery
	e.doJSON("POST", "/v1/send", aliceKey, map[string]any{"to": []string{"dave@local"}, "note": "let me in"}, &rej)
	if len(rej.Delivered) != 1 || rej.Delivered[0]["via"] != "rejected" {
		t.Fatalf("alice→closed dave via = %+v, want rejected", rej.Delivered)
	}
	var dmain, dquar inbox
	e.doJSON("GET", "/v1/inbox", daveKey, nil, &dmain)
	e.doJSON("GET", "/v1/inbox?quarantined=1", daveKey, nil, &dquar)
	if len(dmain.Messages) != 0 || len(dquar.Messages) != 0 {
		t.Fatalf("closed dave should have nothing, main=%d quar=%d", len(dmain.Messages), len(dquar.Messages))
	}
}

// A malformed or bare-name recipient is a clean 400 before the relay is ever
// touched — not a 502 leaking SMTP internals. Regression for battle-test B1.
func TestSendRejectsBadRecipient(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	// Bare name (no @): rejected with an agent-first hint toward name@instance.
	if code := e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"bob"}, "note": "hi"}, nil); code != 400 {
		t.Fatalf("send to bare name: want 400 got %d", code)
	}
	// Syntactically invalid address: rejected before the relay.
	if code := e.doJSON("POST", "/v1/send", key, map[string]any{"to": []string{"weird@@double"}, "note": "hi"}, nil); code != 400 {
		t.Fatalf("send to malformed address: want 400 got %d", code)
	}
}

// Visible identity: the computed tier + selectively-disclosed public_contact show
// up on whoami / card / pubkey, and the A2A Agent Card is served and well-formed.
func TestVisibleIdentityAndAgentCard(t *testing.T) {
	e := newEnv(t) // no DOMAIN → not domain-attested; createAgent is admin → owner-verified
	_, aliceKey := e.createAgent("alice")

	var who struct {
		Verified struct {
			Tier           string `json:"tier"`
			Domain         string `json:"domain"`
			DomainAttested bool   `json:"domain_attested"`
		} `json:"verified"`
		PublicContact string `json:"public_contact"`
	}
	if code := e.doJSON("GET", "/v1/whoami", aliceKey, nil, &who); code != 200 {
		t.Fatalf("whoami: %d", code)
	}
	if who.Verified.Tier != "owner" || who.Verified.DomainAttested {
		t.Fatalf("tier=%q domain_attested=%v, want owner/false", who.Verified.Tier, who.Verified.DomainAttested)
	}

	// public_contact round-trips (selective disclosure); owner_email never appears.
	e.doJSON("POST", "/v1/agents/self/settings", aliceKey, map[string]any{"public_contact": "support@alice.example"}, nil)
	if code := e.doJSON("GET", "/v1/whoami", aliceKey, nil, &who); code != 200 || who.PublicContact != "support@alice.example" {
		t.Fatalf("public_contact: %d %q", code, who.PublicContact)
	}

	// A listed card carries the verified tier + public_contact.
	var card store.Card
	e.doJSON("PUT", "/v1/agents/self/card", aliceKey, map[string]any{"description": "renders scenes", "listed": true}, &card)
	if card.Verified == nil || card.PublicContact != "support@alice.example" {
		t.Fatalf("card missing verified/contact: %+v", card)
	}

	// The pubkey lookup exposes the tier too (once a key is published).
	_, bobKey := e.createAgent("bob")
	e.doJSON("POST", "/v1/agents/self/settings", aliceKey, map[string]any{"pubkey": testRecipient(t)}, nil)
	var pk struct {
		Verified struct {
			Tier string `json:"tier"`
		} `json:"verified"`
	}
	if code := e.doJSON("GET", "/v1/agents/alice/pubkey", bobKey, nil, &pk); code != 200 || pk.Verified.Tier != "owner" {
		t.Fatalf("pubkey verified: %d %q", code, pk.Verified.Tier)
	}

	// The A2A Agent Card is public and well-formed.
	var ac struct {
		Name            string           `json:"name"`
		ProtocolVersion string           `json:"protocolVersion"`
		Skills          []map[string]any `json:"skills"`
		SecuritySchemes map[string]any   `json:"securitySchemes"`
	}
	if code := e.doJSON("GET", "/.well-known/agent-card.json", "", nil, &ac); code != 200 {
		t.Fatalf("agent-card: %d", code)
	}
	if ac.Name != "agenttransfer" || ac.ProtocolVersion == "" || len(ac.Skills) == 0 || ac.SecuritySchemes["bearer"] == nil {
		t.Fatalf("agent-card malformed: %+v", ac)
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
