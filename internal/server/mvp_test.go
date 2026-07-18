package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
)

// newEnvCfg is newEnv with a caller-supplied config.
func newEnvCfg(t *testing.T, cfg Config) *env {
	t.Helper()
	cfg.DataDir = t.TempDir()
	cfg.Metrics = "off"
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppDomain != "" {
		// Reserved test domains do not have real DNS. Treat their wildcard as
		// ready unless a readiness-specific test overrides this cache.
		srv.appReady = appHostingReadiness{WildcardDNSReady: true, CheckedAt: time.Now()}
	}
	t.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.SetBaseURL(ts.URL)
	return &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}
}

// ---- a local SMTP sink standing in for the outbound relay ----

type sinkMsg struct {
	From  string
	Rcpts []string
	Data  []byte
}

type smtpSink struct {
	mu   sync.Mutex
	msgs []sinkMsg
}

func (b *smtpSink) NewSession(*gosmtp.Conn) (gosmtp.Session, error) {
	return &sinkSession{b: b}, nil
}

func (b *smtpSink) all() []sinkMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]sinkMsg{}, b.msgs...)
}

type sinkSession struct {
	b     *smtpSink
	from  string
	rcpts []string
}

func (s *sinkSession) Mail(from string, _ *gosmtp.MailOptions) error { s.from = from; return nil }
func (s *sinkSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	s.rcpts = append(s.rcpts, to)
	return nil
}
func (s *sinkSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.b.mu.Lock()
	s.b.msgs = append(s.b.msgs, sinkMsg{From: s.from, Rcpts: append([]string{}, s.rcpts...), Data: data})
	s.b.mu.Unlock()
	return nil
}
func (s *sinkSession) Reset()        { s.from = ""; s.rcpts = nil }
func (s *sinkSession) Logout() error { return nil }

// newSMTPSink runs an accept-everything SMTP server and returns its address.
func newSMTPSink(t *testing.T) (addr string, sink *smtpSink) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink = &smtpSink{}
	srv := gosmtp.NewServer(sink)
	srv.Domain = "sink.test"
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), sink
}

// ---- signup ergonomics ----

// Open signup must never fail on a taken name — the requested name gets a
// random suffix. Admins asking for an exact name still get the error.
func TestOpenSignupNameCollisionSuffix(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true})

	var first struct {
		Name string `json:"name"`
	}
	code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "openclaw-dev", "owner_email": "a@x.test"}, &first)
	if code != 201 || first.Name != "openclaw-dev" {
		t.Fatalf("first signup: %d %q", code, first.Name)
	}

	var second struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	code = e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "openclaw-dev", "owner_email": "b@x.test"}, &second)
	if code != 201 {
		t.Fatalf("collision signup: %d", code)
	}
	if !strings.HasPrefix(second.Name, "openclaw-dev-") || len(second.Name) != len("openclaw-dev-")+4 {
		t.Fatalf("expected suffixed name, got %q", second.Name)
	}
	if second.Note == "" {
		t.Fatalf("suffixed signup should carry a note explaining the rename")
	}

	// Admin duplicates fail loudly instead of renaming silently.
	code = e.doJSON("POST", "/v1/agents", e.admin, map[string]string{"name": "openclaw-dev"}, nil)
	if code != 400 {
		t.Fatalf("admin duplicate: %d, want 400", code)
	}
}

// Reserved localparts (postmaster, no-reply, abuse, …) are open-signup-proof
// but remain admin-creatable.
func TestReservedNamesBlocked(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true})
	for _, name := range []string{"abuse", "postmaster", "no-reply", "upload-request", "self"} {
		code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": name, "owner_email": "a@x.test"}, nil)
		if code != 400 {
			t.Fatalf("open signup of reserved %q: %d, want 400", name, code)
		}
	}
	code := e.doJSON("POST", "/v1/agents", e.admin, map[string]string{"name": "abuse"}, nil)
	if code != 201 {
		t.Fatalf("admin create of reserved name: %d, want 201", code)
	}
}

// ---- verification: GET is side-effect-free, POST consumes ----

func TestVerifyConfirmFlow(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true})

	var agent struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "owner_email": "sam@x.test"}, &agent)
	if code != 201 {
		t.Fatalf("signup: %d", code)
	}
	tok, err := e.srv.Store().CreateVerifyToken(agent.AgentID)
	if err != nil {
		t.Fatal(err)
	}

	verified := func() bool {
		var who struct {
			OwnerVerified bool `json:"owner_verified"`
		}
		e.doJSON("GET", "/v1/whoami", agent.APIKey, nil, &who)
		return who.OwnerVerified
	}

	// A scanner prefetching the link (GET) must not verify.
	resp, body := e.do("GET", "/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("Confirm")) {
		t.Fatalf("verify page: HTTP %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("verify Cache-Control = %q", got)
	}
	for _, disclosure := range []string{"full persistent storage", "publish an app or website"} {
		if !bytes.Contains(body, []byte(disclosure)) {
			t.Fatalf("verification page omitted %q consent: %s", disclosure, body)
		}
	}
	if verified() {
		t.Fatal("GET /verify consumed the token — scanner-clickable verification")
	}

	// The explicit confirm click (POST) verifies.
	resp, _ = e.do("POST", "/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("verify confirm: HTTP %d", resp.StatusCode)
	}
	if !verified() {
		t.Fatal("POST /verify did not verify")
	}

	// The token is single-use.
	resp, _ = e.do("POST", "/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 404 {
		t.Fatalf("verify replay: HTTP %d, want 404", resp.StatusCode)
	}
	resp, _ = e.do("GET", "/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 404 {
		t.Fatalf("verify page after consume: HTTP %d, want 404", resp.StatusCode)
	}
}

// The connect-host owner verification gets the same GET/POST split.
func TestConnectVerifyConfirmFlow(t *testing.T) {
	e := newEnvCfg(t, Config{Domain: "hub.test", ConnectDomain: "hub.test"})
	if _, err := e.srv.Store().CreateConnectInstance("misty-owl-11"); err != nil {
		t.Fatal(err)
	}
	tok, err := e.srv.Store().CreateVerifyToken("connect:misty-owl-11:owner@x.test")
	if err != nil {
		t.Fatal(err)
	}

	resp, body := e.do("GET", "/connect/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("Confirm")) {
		t.Fatalf("connect verify page: HTTP %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("connect verify Cache-Control = %q", got)
	}
	if ci, _ := e.srv.Store().ConnectInstanceByName("misty-owl-11"); ci.Verified {
		t.Fatal("GET /connect/verify verified the instance")
	}

	resp, _ = e.do("POST", "/connect/verify?t="+url.QueryEscape(tok), "", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("connect verify confirm: HTTP %d", resp.StatusCode)
	}
	ci, err := e.srv.Store().ConnectInstanceByName("misty-owl-11")
	if err != nil || !ci.Verified {
		t.Fatalf("instance not verified: %+v err=%v", ci, err)
	}
}

// ---- the recipient circle ----

func TestSignupCanonicalizesOwnerMailbox(t *testing.T) {
	e := newEnv(t)
	var out struct {
		AgentID    string `json:"agent_id"`
		OwnerEmail string `json:"owner_email"`
	}
	if code := e.doJSON(http.MethodPost, "/v1/agents", e.admin, map[string]any{
		"name": "canonical-owner", "owner_email": "Alice Example <ALICE@EXAMPLE.COM>",
	}, &out); code != http.StatusCreated {
		t.Fatalf("signup: HTTP %d", code)
	}
	if out.OwnerEmail != "alice@example.com" {
		t.Fatalf("owner email = %q", out.OwnerEmail)
	}
	agent, err := e.srv.st.AgentByID(out.AgentID)
	if err != nil || agent.OwnerEmail != "alice@example.com" {
		t.Fatalf("stored agent = %+v err=%v", agent, err)
	}
}

func TestRecipientCircle(t *testing.T) {
	sinkAddr, sink := newSMTPSink(t)
	e := newEnvCfg(t, Config{Domain: "agents.test", Outbound: "smtp://" + sinkAddr})

	// Admin-created with an owner: verified from birth, owner exempt.
	var alice struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	code := e.doJSON("POST", "/v1/agents", e.admin, map[string]any{"name": "alice", "owner_email": "sam@own.test"}, &alice)
	if code != 201 {
		t.Fatalf("create alice: %d", code)
	}
	send := func(to string, ccOwner bool) (int, map[string]any) {
		var out map[string]any
		code := e.doJSON("POST", "/v1/send", alice.APIKey, map[string]any{"to": []string{to}, "note": "hi", "cc_owner": ccOwner}, &out)
		return code, out
	}
	circleUsed := func() float64 {
		var who struct {
			Remote struct {
				Used float64 `json:"used"`
				Max  float64 `json:"max"`
			} `json:"remote_recipients"`
		}
		e.doJSON("GET", "/v1/whoami", alice.APIKey, nil, &who)
		return who.Remote.Used
	}

	// Three unique remote recipients fill the default circle.
	for _, to := range []string{"h1@x.test", "h2@x.test", "h3@x.test"} {
		if code, _ := send(to, false); code != 201 {
			t.Fatalf("send to %s: %d", to, code)
		}
	}
	if n := circleUsed(); n != 3 {
		t.Fatalf("circle used = %v, want 3", n)
	}

	// A fourth unique stranger is refused; a repeat and the owner are free.
	if code, _ := send("h4@x.test", false); code != 403 {
		t.Fatalf("4th unique recipient: %d, want 403", code)
	}
	if code, _ := send("h1@x.test", false); code != 201 {
		t.Fatalf("repeat recipient: %d, want 201", code)
	}
	if code, _ := send("sam@own.test", false); code != 201 {
		t.Fatalf("owner as recipient: %d, want 201", code)
	}
	// Display names are accepted at the API edge but canonicalized before the
	// SMTP envelope, suppression keys, and recipient-circle accounting.
	if code, _ := send("Human One <H1@X.TEST>", false); code != 201 {
		t.Fatalf("display-name repeat recipient: %d, want 201", code)
	}
	if n := circleUsed(); n != 3 {
		t.Fatalf("circle used after repeat+owner = %v, want 3", n)
	}

	// cc_owner rides free too.
	if code, out := send("h2@x.test", true); code != 201 || out["cc_owner"] != "sent to sam@own.test" {
		t.Fatalf("cc_owner send: %d %v", code, out["cc_owner"])
	}
	// Addressing the owner directly and requesting cc_owner is still one
	// message, not a duplicate accountability copy.
	beforeOwner := len(sink.all())
	if code, out := send("SAM@OWN.TEST", true); code != 201 || out["cc_owner"] != "already included as recipient" {
		t.Fatalf("owner recipient + cc_owner: %d %v", code, out["cc_owner"])
	}
	if got := len(sink.all()) - beforeOwner; got != 1 {
		t.Fatalf("owner recipient + cc_owner relayed %d messages, want 1", got)
	}

	// The operator can widen the circle.
	code = e.doJSON("POST", "/v1/agents/"+alice.AgentID+"/limits", e.admin, map[string]any{"human_recipients_max": 5}, nil)
	if code != 200 {
		t.Fatalf("limits: %d", code)
	}
	if code, _ := send("h4@x.test", false); code != 201 {
		t.Fatalf("post-raise send: %d, want 201", code)
	}

	// Every relayed mail went out one-recipient-per-message, and every mail
	// to a non-owner human carries an unsubscribe footer. (Mail addressed TO
	// the owner directly gets one too — they're a recipient like any other;
	// only the cc_owner accountability copy is built without it.) The bodies
	// are quoted-printable, so parse rather than grep the raw bytes.
	for _, m := range sink.all() {
		if len(m.Rcpts) != 1 {
			t.Fatalf("expected single-recipient messages, got %v", m.Rcpts)
		}
		if strings.ContainsAny(m.Rcpts[0], "<>") {
			t.Fatalf("SMTP envelope retained display-name syntax: %q", m.Rcpts[0])
		}
		in, err := mail.ParseInbound(bytes.NewReader(m.Data), 1<<20)
		if err != nil {
			t.Fatalf("relayed mail unparseable: %v", err)
		}
		if isOwner := strings.Contains(m.Rcpts[0], "sam@own.test"); !isOwner &&
			!strings.Contains(in.Text, "/unsubscribe?e=") {
			t.Fatalf("human mail without unsubscribe link: %v\n%s", m.Rcpts, in.Text)
		}
	}
}

// A send whose relay fails must refund the circle slot — a typo'd address
// can't burn the cap.
func TestCircleReleasedOnRelayFailure(t *testing.T) {
	e := newEnvCfg(t, Config{Domain: "agents.test", Outbound: "smtp://127.0.0.1:1"})
	var alice struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if code := e.doJSON("POST", "/v1/agents", e.admin, map[string]any{"name": "alice", "owner_email": "sam@own.test"}, &alice); code != 201 {
		t.Fatalf("create alice: %d", code)
	}
	e.upload(alice.APIKey, "failed.bin", []byte("failed send bytes"), "")
	payload, _ := json.Marshal(map[string]any{"to": []string{"typo@nowhere.test"}, "file": "failed.bin", "note": "hi"})
	resp, _ := e.do("POST", "/v1/send", alice.APIKey, bytes.NewReader(payload), "application/json", "Idempotency-Key", "failed-send")
	if resp.StatusCode != 502 {
		t.Fatalf("dead-relay send: %d, want 502", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/v1/send", alice.APIKey, bytes.NewReader(payload), "application/json", "Idempotency-Key", "failed-send")
	if resp.StatusCode != 502 || resp.Header.Get("Idempotent-Replay") != "true" {
		t.Fatalf("failed-send replay: HTTP %d replay=%q", resp.StatusCode, resp.Header.Get("Idempotent-Replay"))
	}
	n, err := e.srv.Store().CountHumanRecipients(alice.AgentID)
	if err != nil || n != 0 {
		t.Fatalf("failed send left %d circle slots claimed (err=%v)", n, err)
	}
	links, err := e.srv.Store().ListLinks(alice.AgentID)
	if err != nil || len(links) != 1 || links[0].Status != "revoked" {
		t.Fatalf("failed send links=%+v err=%v, want one revoked audit row", links, err)
	}
	if sends, err := e.srv.Store().IncrCounterN(alice.AgentID, "sends", 0); err != nil || sends != 0 {
		t.Fatalf("failed send rate counter=%d err=%v, want refunded", sends, err)
	}
}

// ---- quota tiers ----

func TestUnverifiedQuotaTier(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true, StorageQuota: 1 << 20, StorageQuotaUnverified: 512})

	var agent struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "owner_email": "sam@x.test"}, &agent); code != 201 {
		t.Fatalf("signup: %d", code)
	}

	// 600 bytes exceeds the unverified tier (512)…
	resp, body := e.do("PUT", "/v1/files/big.bin", agent.APIKey, bytes.NewReader(bytes.Repeat([]byte("x"), 600)), "application/octet-stream")
	if resp.StatusCode != 413 || !bytes.Contains(body, []byte("verify")) {
		t.Fatalf("unverified upload: HTTP %d %s", resp.StatusCode, body)
	}

	// MCP whoami must report the SAME enforced (reduced) quota as REST — not
	// the full tier — so an agent isn't told 20GB while 512 is enforced.
	mcpQuota := func() float64 {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": "whoami", "arguments": map[string]any{}}})
		_, data := e.do("POST", "/mcp", agent.APIKey, bytes.NewReader(body), "application/json")
		var out struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &out); err != nil || len(out.Result.Content) == 0 {
			t.Fatalf("mcp whoami: %s", data)
		}
		var who struct {
			StorageQuota float64 `json:"storage_quota"`
		}
		_ = json.Unmarshal([]byte(out.Result.Content[0].Text), &who)
		return who.StorageQuota
	}
	if q := mcpQuota(); q != 512 {
		t.Fatalf("mcp whoami quota (unverified) = %v, want 512 (the enforced tier)", q)
	}

	// …and fits once the owner is verified.
	if code := e.doJSON("POST", "/v1/agents/"+agent.AgentID+"/verify", e.admin, map[string]any{}, nil); code != 200 {
		t.Fatalf("admin verify: %d", code)
	}
	resp, _ = e.do("PUT", "/v1/files/big.bin", agent.APIKey, bytes.NewReader(bytes.Repeat([]byte("x"), 600)), "application/octet-stream")
	if resp.StatusCode != 201 {
		t.Fatalf("verified upload: HTTP %d", resp.StatusCode)
	}
	if q := mcpQuota(); q != 1<<20 {
		t.Fatalf("mcp whoami quota (verified) = %v, want %d", q, 1<<20)
	}
}

// ---- delete agent ----

// Deleting an agent removes it and everything it owns, releases its blob refs
// WITHOUT harming content another agent still references, severs its links,
// and, critically, leaves the signed receipt chain intact and still
// deletion-evident.
func TestDeleteAgent(t *testing.T) {
	e := newEnvCfg(t, Config{})
	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")
	aliceID := agentIDByKey(t, e.srv, aliceKey)

	// Shared content: alice and bob both upload the SAME bytes (deduped to one
	// blob, refs=2). Alice also shares a link over it.
	shared := []byte("shared bytes both agents hold")
	e.upload(aliceKey, "shared.bin", shared, "?share=1")
	e.upload(bobKey, "shared.bin", shared, "")
	sha := func() string {
		var out struct {
			Files []struct {
				SHA256 string `json:"sha256"`
			} `json:"files"`
		}
		e.doJSON("GET", "/v1/files", bobKey, nil, &out)
		return out.Files[0].SHA256
	}()

	// Alice also has an active link (grab its token for the sever check).
	var links struct {
		Links []struct {
			Token  string `json:"token"`
			Status string `json:"status"`
		} `json:"links"`
	}
	e.doJSON("GET", "/v1/links", aliceKey, nil, &links)
	if len(links.Links) != 1 {
		t.Fatalf("alice should have one link, got %d", len(links.Links))
	}

	// Count alice's receipts before deletion (she uploaded + created a link).
	preAlice, _ := e.srv.Store().ListReceipts("alice@local", 0)
	if len(preAlice) == 0 {
		t.Fatal("expected alice to have receipts before deletion")
	}

	// Admin deletes alice.
	var del struct {
		Deleted      string `json:"deleted"`
		LinksSevered int    `json:"links_severed"`
	}
	code := e.doJSON("DELETE", "/v1/agents/"+aliceID, e.admin, nil, &del)
	if code != 200 || del.Deleted != "alice@local" || del.LinksSevered != 1 {
		t.Fatalf("delete alice: %d %+v", code, del)
	}

	// Alice's key is dead; bob is untouched.
	if c, _ := e.do("GET", "/v1/whoami", aliceKey, nil, ""); c.StatusCode != 401 {
		t.Fatalf("deleted agent's key still works: %d", c.StatusCode)
	}
	var bobFiles struct {
		Files []map[string]any `json:"files"`
	}
	e.doJSON("GET", "/v1/files", bobKey, nil, &bobFiles)
	if len(bobFiles.Files) != 1 {
		t.Fatalf("bob's folder harmed by alice's deletion: %d files", len(bobFiles.Files))
	}

	// The shared blob must SURVIVE (bob still refs it) even after GC.
	if err := e.srv.JanitorOnce(); err != nil {
		t.Fatal(err)
	}
	if blob, err := e.srv.Store().OpenBlob(sha); err != nil {
		t.Fatalf("shared blob was GC'd out from under bob: %v", err)
	} else {
		blob.Close()
	}

	// Alice's receipts are PRESERVED (the chain outlives the account) and now
	// include the deletion event; the full export still chain-verifies.
	postAlice, _ := e.srv.Store().ListReceipts("alice@local", 0)
	if len(postAlice) < len(preAlice)+1 {
		t.Fatalf("alice's receipts not preserved/extended: pre=%d post=%d", len(preAlice), len(postAlice))
	}
	var wk struct {
		ReceiptPubkey string `json:"receipt_pubkey"`
	}
	e.doJSON("GET", "/.well-known/agenttransfer", "", nil, &wk)
	pub, err := receipt.ParsePublicKey(wk.ReceiptPubkey)
	if err != nil {
		t.Fatal(err)
	}
	_, data := e.do("GET", "/v1/receipts/export", e.admin, nil, "")
	rs, err := receipt.ReadJSONL(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyChain(rs, pub, true); err != nil {
		t.Fatalf("chain broken after agent deletion: %v", err)
	}

	// Self-delete: bob removes himself with his own key.
	if code := e.doJSON("DELETE", "/v1/agents/self", bobKey, nil, nil); code != 200 {
		t.Fatalf("self-delete: %d", code)
	}
	if c, _ := e.do("GET", "/v1/whoami", bobKey, nil, ""); c.StatusCode != 401 {
		t.Fatalf("self-deleted key still works: %d", c.StatusCode)
	}
	// The real invariant: with both owners gone, nothing references the shared
	// blob, so orphan GC reclaims it. (GC waits out the young-blob grace period,
	// so age it before sweeping.)
	if _, err := e.srv.Store().DB.Exec(`UPDATE blobs SET created_at=1 WHERE sha256=?`, sha); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.JanitorOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.Store().OpenBlob(sha); err == nil {
		t.Fatal("orphaned blob survived GC after all referencing agents deleted")
	}

	// Deleting a nonexistent agent → 404; non-admin by-id → 403.
	if code := e.doJSON("DELETE", "/v1/agents/agt_nope", e.admin, nil, nil); code != 404 {
		t.Fatalf("delete nonexistent: %d, want 404", code)
	}
	_, ck := e.createAgent("carol")
	if code := e.doJSON("DELETE", "/v1/agents/"+agentIDByKey(t, e.srv, ck), "", nil, nil); code != 403 {
		t.Fatalf("non-admin delete by id: %d, want 403", code)
	}
}

// ---- unsubscribe / suppression ----

func TestUnsubscribeFlow(t *testing.T) {
	sinkAddr, sink := newSMTPSink(t)
	e := newEnvCfg(t, Config{Domain: "agents.test", Outbound: "smtp://" + sinkAddr})

	var alice struct {
		APIKey string `json:"api_key"`
	}
	if code := e.doJSON("POST", "/v1/agents", e.admin, map[string]any{"name": "alice", "owner_email": "sam@own.test"}, &alice); code != 201 {
		t.Fatalf("create alice: %d", code)
	}

	addr := "dana@x.test"
	good := e.srv.Store().UnsubscribeToken(addr)

	// Forged and mismatched tokens are rejected — nobody can suppress a
	// victim's address to block their transfers.
	resp, _ := e.do("GET", "/unsubscribe?e="+url.QueryEscape(addr)+"&t=deadbeef", "", nil, "")
	if resp.StatusCode != 404 {
		t.Fatalf("forged unsubscribe: HTTP %d, want 404", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/unsubscribe?e="+url.QueryEscape("victim@x.test")+"&t="+good, "", nil, "")
	if resp.StatusCode != 404 {
		t.Fatalf("token for another address: HTTP %d, want 404", resp.StatusCode)
	}

	// GET shows the page without suppressing; POST suppresses.
	resp, body := e.do("GET", "/unsubscribe?e="+url.QueryEscape(addr)+"&t="+good, "", nil, "")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("Unsubscribe")) {
		t.Fatalf("unsubscribe page: HTTP %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("unsubscribe Cache-Control = %q", got)
	}
	if e.srv.Store().IsSuppressed(addr) {
		t.Fatal("GET /unsubscribe suppressed the address")
	}
	resp, _ = e.do("POST", "/unsubscribe?e="+url.QueryEscape(addr)+"&t="+good, "", nil, "")
	if resp.StatusCode != 200 || !e.srv.Store().IsSuppressed(addr) {
		t.Fatalf("unsubscribe confirm failed: HTTP %d suppressed=%v", resp.StatusCode, e.srv.Store().IsSuppressed(addr))
	}

	// Sends to the suppressed address are skipped and reported; no mail flows.
	var out struct {
		Delivered []map[string]any `json:"delivered"`
	}
	code := e.doJSON("POST", "/v1/send", alice.APIKey, map[string]any{"to": []string{addr}, "note": "hi"}, &out)
	if code != 201 || len(out.Delivered) != 1 || out.Delivered[0]["via"] != "suppressed" {
		t.Fatalf("suppressed send: %d %+v", code, out.Delivered)
	}
	if n := len(sink.all()); n != 0 {
		t.Fatalf("suppressed recipient still received %d message(s)", n)
	}
}

// ---- storage + IP hardening ----

func TestParseDiskReserve(t *testing.T) {
	cases := []struct {
		in      string
		total   int64
		want    int64
		wantErr bool
	}{
		{"10%", 1000, 100, false},
		{"off", 1000, 0, false},
		{"0", 1000, 0, false},
		{"", 1000, 0, false},
		{"50GB", 0, 50 << 30, false},
		{"150%", 1000, 0, true},
		{"-5%", 1000, 0, true},
		{"nope", 1000, 0, true},
	}
	for _, c := range cases {
		got, err := ParseDiskReserve(c.in, c.total)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("ParseDiskReserve(%q, %d) = %d, %v — want %d, err=%v", c.in, c.total, got, err, c.want, c.wantErr)
		}
	}
}

// The global disk guard refuses every upload entry point with 507 while the
// volume is under the reserve, consumes nothing (one-time upload pages stay
// valid), and lifts cleanly.
func TestDiskGuard(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("alice")
	e.upload(key, "before.bin", []byte("fits fine"), "")

	// A reserve larger than any real volume's free space trips the guard.
	e.srv.Store().SetDiskReserve(1 << 62)

	resp, body := e.do("PUT", "/v1/files/x.bin", key, bytes.NewReader([]byte("data")), "application/octet-stream")
	if resp.StatusCode != 507 {
		t.Fatalf("upload with full disk: HTTP %d %s, want 507", resp.StatusCode, body)
	}

	var reqOut struct {
		UploadURL string `json:"upload_url"`
	}
	e.doJSON("POST", "/v1/requests", key, map[string]any{"note": "x"}, &reqOut)
	page := strings.TrimPrefix(reqOut.UploadURL, e.ts.URL)
	form := func() (*bytes.Buffer, string) {
		var mp bytes.Buffer
		w := multipart.NewWriter(&mp)
		fw, _ := w.CreateFormFile("file", "f.txt")
		fw.Write([]byte("hi"))
		w.Close()
		return &mp, w.FormDataContentType()
	}
	mp, ctype := form()
	resp, _ = e.do("POST", page, "", mp, ctype)
	if resp.StatusCode != 507 {
		t.Fatalf("page upload with full disk: HTTP %d, want 507", resp.StatusCode)
	}

	// The admin dashboard shows the tripped guard and the consumers.
	var st struct {
		Volume struct {
			UploadsRefused bool `json:"uploads_refused"`
		} `json:"volume"`
		Agents []map[string]any `json:"agents"`
	}
	if code := e.doJSON("GET", "/v1/admin/storage", e.admin, nil, &st); code != 200 {
		t.Fatalf("admin storage: %d", code)
	}
	if !st.Volume.UploadsRefused || len(st.Agents) == 0 {
		t.Fatalf("admin storage view wrong: %+v", st)
	}
	if code := e.doJSON("GET", "/v1/admin/storage", key, nil, nil); code != 403 {
		t.Fatalf("non-admin storage view: %d, want 403", code)
	}

	// Guard lifted: uploads work again and the page token SURVIVED the 507.
	e.srv.Store().SetDiskReserve(0)
	resp, _ = e.do("PUT", "/v1/files/x.bin", key, bytes.NewReader([]byte("data")), "application/octet-stream")
	if resp.StatusCode != 201 {
		t.Fatalf("upload after guard lift: HTTP %d", resp.StatusCode)
	}
	mp, ctype = form()
	resp, _ = e.do("POST", page, "", mp, ctype)
	if resp.StatusCode != 200 {
		t.Fatalf("page upload after guard lift: HTTP %d — the refusal burned the one-time token", resp.StatusCode)
	}
}

// Merely nominating a mailbox at signup does not consume its verified-agent
// cap; only a successful mailbox challenge claims a slot.
func TestPendingOwnerClaimsDoNotConsumeVerifiedCap(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true, MaxAgentsPerOwner: 2})
	for _, name := range []string{"one-agent", "two-agent", "three-agent"} {
		if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": name, "owner_email": "Sam@x.test"}, nil); code != 201 {
			t.Fatalf("signup %s: %d", name, code)
		}
	}
	if n, err := e.srv.st.CountAgentsByOwner("sam@x.test"); err != nil || n != 0 {
		t.Fatalf("unproven nominations consumed %d verified slots (err=%v)", n, err)
	}
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "other-agent", "owner_email": "dana@x.test"}, nil); code != 201 {
		t.Fatalf("different owner blocked: %d", code)
	}
	if code := e.doJSON("POST", "/v1/agents", e.admin, map[string]any{"name": "adm-agent", "owner_email": "sam@x.test"}, nil); code != 201 {
		t.Fatalf("admin create failed: %d", code)
	}
}

// IPv6 addresses rate-limit by /64 — a v6 host owns its whole /64, so full
// addresses would be 2^64 free identities.
func TestIPKeyV6Prefix(t *testing.T) {
	if k := ipKey("203.0.113.7"); k != "203.0.113.7" {
		t.Fatalf("v4 key = %q", k)
	}
	if k := ipKey("::ffff:203.0.113.7"); k != "203.0.113.7" {
		t.Fatalf("4-in-6 should unmap, got %q", k)
	}
	a := ipKey("2001:db8:1:2:aaaa::1")
	b := ipKey("2001:db8:1:2:bbbb:cccc:dddd:2")
	if a != b {
		t.Fatalf("same /64 must share a key: %q vs %q", a, b)
	}
	if c := ipKey("2001:db8:1:3::1"); c == a {
		t.Fatal("different /64s must not share a key")
	}
	if k := ipKey("not-an-ip"); k != "not-an-ip" {
		t.Fatalf("unparseable input should key as itself, got %q", k)
	}
}

// The per-IP limiter guards the public identity-free pages; authenticated
// routes stay governed by per-agent counters only.
func TestUnauthPerIPLimit(t *testing.T) {
	e := newEnvCfg(t, Config{IPRate: 3})
	for i := 0; i < 3; i++ {
		resp, _ := e.do("GET", "/", "", nil, "")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: HTTP %d", i, resp.StatusCode)
		}
	}
	resp, _ := e.do("GET", "/", "", nil, "")
	if resp.StatusCode != 429 {
		t.Fatalf("over-limit request: HTTP %d, want 429", resp.StatusCode)
	}
	_, key := e.createAgent("alice")
	for i := 0; i < 5; i++ {
		if code := e.doJSON("GET", "/v1/whoami", key, nil, nil); code != 200 {
			t.Fatalf("authed request %d was IP-limited: %d", i, code)
		}
	}
}

// A client that trickles its upload body hits the read deadline; nothing is
// committed either way.
func TestUploadBodyTimeout(t *testing.T) {
	e := newEnvCfg(t, Config{UploadBodyTimeout: 200 * time.Millisecond})
	_, key := e.createAgent("alice")

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("start"))
		time.Sleep(700 * time.Millisecond)
		_, _ = pw.Write([]byte("the rest, far too late"))
		pw.Close()
	}()
	req, err := http.NewRequest("PUT", e.ts.URL+"/v1/files/slow.bin", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := e.client.Do(req)
	if err == nil {
		if resp.StatusCode != 408 {
			t.Fatalf("slow upload: HTTP %d, want 408", resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Whether the client saw the 408 or a torn connection, nothing may have
	// been committed.
	var files struct {
		Files []map[string]any `json:"files"`
	}
	e.doJSON("GET", "/v1/files", key, nil, &files)
	if len(files.Files) != 0 {
		t.Fatalf("slow upload committed a file: %+v", files.Files)
	}
}

// The unverified storage tier: files uploaded before the owner verifies are
// mortal (expire via the janitor even though claimed), keeping an arrival
// only extends to the tier ceiling, and verification lifts the expiry on
// everything the agent holds.
func TestUnverifiedFileTierExpiry(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true, UnverifiedFileTTL: time.Hour})

	var agent struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "wanderer", "owner_email": "sam@x.test"}, &agent); code != 201 {
		t.Fatalf("signup: %d", code)
	}

	// An unverified agent's own upload comes back mortal.
	up := e.upload(agent.APIKey, "scratch.bin", []byte("mortal bytes"), "")
	if up["expires_at"] == nil || up["expires_at"] == "" {
		t.Fatalf("unverified upload should carry expires_at: %v", up)
	}
	sha := up["sha256"].(string)

	// Keep must not grant immortality the tier doesn't allow.
	var kept map[string]any
	if code := e.doJSON("POST", "/v1/files/"+sha+"/keep", agent.APIKey, map[string]any{}, &kept); code != 200 {
		t.Fatalf("keep: %d", code)
	}
	if kept["expires_at"] == nil || kept["expires_at"] == "" {
		t.Fatalf("unverified keep should stay mortal: %v", kept)
	}

	// The janitor expires it despite claimed=1.
	if _, err := e.srv.Store().DB.Exec(`UPDATE files SET expires_at=1 WHERE agent_id=?`, agent.AgentID); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.JanitorOnce(); err != nil {
		t.Fatal(err)
	}
	var files struct {
		Files []map[string]any `json:"files"`
	}
	e.doJSON("GET", "/v1/files", agent.APIKey, nil, &files)
	if len(files.Files) != 0 {
		t.Fatalf("unverified tier file survived the janitor: %+v", files.Files)
	}

	// Upload again, then verify the owner: the expiry lifts on the existing
	// file, and new uploads are born persistent.
	e.upload(agent.APIKey, "keeper.bin", []byte("about to become permanent"), "")
	if code := e.doJSON("POST", "/v1/agents/"+agent.AgentID+"/verify", e.admin, map[string]any{}, nil); code != 200 {
		t.Fatalf("admin verify: %d", code)
	}
	e.doJSON("GET", "/v1/files", agent.APIKey, nil, &files)
	if len(files.Files) != 1 || files.Files[0]["expires_at"] != nil {
		t.Fatalf("verification did not lift the expiry: %+v", files.Files)
	}
	up = e.upload(agent.APIKey, "fresh.bin", []byte("born persistent"), "")
	if up["expires_at"] != nil && up["expires_at"] != "" {
		t.Fatalf("verified upload should be persistent: %v", up)
	}
}
