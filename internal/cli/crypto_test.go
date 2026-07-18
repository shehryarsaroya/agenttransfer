package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

func testConfigHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("AGENTTRANSFER_URL", "")
	t.Setenv("AGENTTRANSFER_KEY", "")
	t.Setenv("AGENTTRANSFER_IDENTITY", "")
}

func TestEnvLoginDoesNotBorrowUnrelatedIdentity(t *testing.T) {
	testConfigHome(t)
	id, err := seal.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(clientConfig{URL: "https://saved.test", APIKey: "saved-key", AgentID: "agt_saved", Identity: id.Secret()}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTTRANSFER_URL", "https://other.test")
	t.Setenv("AGENTTRANSFER_KEY", "other-key")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity != "" {
		t.Fatal("unrelated environment login reused the saved X25519 identity")
	}
}

func TestIdempotencyKeyGenerationReturnsEntropyFailures(t *testing.T) {
	key, err := idempotencyKeyFrom(strings.NewReader(strings.Repeat("x", 16)))
	if err != nil || key != "cli_"+strings.Repeat("78", 16) {
		t.Fatalf("key = %q err=%v", key, err)
	}
	if _, err := idempotencyKeyFrom(strings.NewReader("short")); err == nil || !strings.Contains(err.Error(), "generate idempotency key") {
		t.Fatalf("short entropy error = %v", err)
	}
}

func TestPrepareIdempotencyKeyMatchesServerSyntax(t *testing.T) {
	if got, err := prepareIdempotencyKey("  retry-key  "); err != nil || got != "retry-key" {
		t.Fatalf("trimmed key = %q err=%v", got, err)
	}
	for _, key := range []string{"has space", "line\nbreak", "café", strings.Repeat("x", 129)} {
		if _, err := prepareIdempotencyKey(key); err == nil {
			t.Errorf("accepted invalid idempotency key %q", key)
		}
	}
}

func TestMatchingEnvLoginLoadsPinsWithExplicitIdentity(t *testing.T) {
	testConfigHome(t)
	saved, _ := seal.NewIdentity()
	explicit, _ := seal.NewIdentity()
	wantPins := map[string]string{"scope#recipient=bob@agents.test": "age1pinned"}
	if err := saveConfig(clientConfig{
		URL: "https://agents.test", APIKey: "same-key", AgentID: "agt_same",
		Identity: saved.Secret(), RecipientPins: wantPins,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTTRANSFER_URL", "https://agents.test")
	t.Setenv("AGENTTRANSFER_KEY", "same-key")
	t.Setenv("AGENTTRANSFER_IDENTITY", explicit.Secret())
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentID != "agt_same" || c.Identity != explicit.Secret() || c.RecipientPins["scope#recipient=bob@agents.test"] != "age1pinned" {
		t.Fatalf("matching environment login lost saved key state: %+v", c)
	}
}

func TestPersistingPinsFromMatchingEnvPreservesSavedIdentity(t *testing.T) {
	testConfigHome(t)
	saved, _ := seal.NewIdentity()
	explicit, _ := seal.NewIdentity()
	base := "https://agents.test"
	fileConfig := clientConfig{
		URL: base, APIKey: "same-key", AgentID: "agt_same",
		Identity: saved.Secret(),
	}
	if err := saveConfig(fileConfig); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTTRANSFER_URL", base)
	t.Setenv("AGENTTRANSFER_KEY", "same-key")
	t.Setenv("AGENTTRANSFER_IDENTITY", explicit.Secret())
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.RecipientPins = map[string]string{recipientPinSlot(c, "bob@agents.test"): "age1pinned"}
	if err := persistKeyState(c); err != nil {
		t.Fatal(err)
	}
	got, err := readFileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != saved.Secret() || got.Identities[identitySlot(base, "agt_same")] != saved.Secret() {
		t.Fatal("temporary AGENTTRANSFER_IDENTITY replaced the saved account identity")
	}
	if got.RecipientPins[recipientPinSlot(fileConfig, "bob@agents.test")] != "age1pinned" {
		t.Fatalf("recipient pins = %#v", got.RecipientPins)
	}
}

func TestSplitAddrRejectsMalformedAddresses(t *testing.T) {
	for _, address := range []string{"", "alice", "@agents.test", "alice@", "alice@agents.test@evil.test"} {
		if _, _, ok := splitAddr(address); ok {
			t.Errorf("splitAddr(%q) accepted malformed address", address)
		}
	}
	if local, domain, ok := splitAddr(" Alice@Agents.Test "); !ok || local != "alice" || domain != "agents.test" {
		t.Fatalf("valid address = %q@%q ok=%v", local, domain, ok)
	}
}

func TestLoginScopesIdentityPerInstanceAccount(t *testing.T) {
	testConfigHome(t)
	oldID, _ := seal.NewIdentity()
	if err := saveConfig(clientConfig{URL: "https://old.test", APIKey: "old-key", AgentID: "agt_old", Identity: oldID.Secret()}); err != nil {
		t.Fatal(err)
	}

	var published string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			writeTestJSON(w, map[string]any{"agent_id": "agt_new", "email": "new@agents.test"})
		case "/v1/agents/self/settings":
			var body struct {
				Pubkey string `json:"pubkey"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			published = body.Pubkey
			writeTestJSON(w, map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	if err := cmdLogin([]string{srv.URL, "--key", "new-key"}); err != nil {
		t.Fatal(err)
	}
	c, err := readFileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentID != "agt_new" || c.Identity == "" || c.Identity == oldID.Secret() {
		t.Fatalf("new account identity was not isolated: %+v", c)
	}
	newID, err := seal.ParseIdentity(c.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if published != newID.Recipient() {
		t.Fatalf("published %q, want local %q", published, newID.Recipient())
	}
	if c.Identities[identitySlot("https://old.test", "agt_old")] != oldID.Secret() {
		t.Fatal("inactive account identity was not retained in keyring")
	}
}

func TestLoginReusesIdentityForSameAccount(t *testing.T) {
	testConfigHome(t)
	id, _ := seal.NewIdentity()

	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			writeTestJSON(w, map[string]any{"agent_id": "agt_same", "email": "same@agents.test"})
		case "/v1/agents/self/settings":
			writeTestJSON(w, map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL
	if err := saveConfig(clientConfig{URL: base, APIKey: "old-key", AgentID: "agt_same", Identity: id.Secret()}); err != nil {
		t.Fatal(err)
	}

	if err := cmdLogin([]string{base, "--key", "new-key"}); err != nil {
		t.Fatal(err)
	}
	c, _ := readFileConfig()
	if c.Identity != id.Secret() {
		t.Fatal("same account did not preserve its sealed-transfer identity")
	}
}

func TestRecipientKeyTOFURejectsSubstitutionUntilRepinned(t *testing.T) {
	testConfigHome(t)
	self, _ := seal.NewIdentity()
	first, _ := seal.NewIdentity()
	changed, _ := seal.NewIdentity()
	operator, _ := seal.NewIdentity()
	current := first.Recipient()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			// The server-advertised sender key is malicious and must be ignored.
			writeTestJSON(w, map[string]any{"instance": "agents.test", "pubkey": operator.Recipient()})
		case "/v1/agents/bob/pubkey":
			writeTestJSON(w, map[string]any{"pubkey": current})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := clientConfig{URL: srv.URL, APIKey: "key", AgentID: "agt_sender", Identity: self.Secret()}
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}

	keys, notes, err := resolveRecipientKeys(newAPI(c), &c, []string{"bob@agents.test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || !containsString(keys, self.Recipient()) || !containsString(keys, first.Recipient()) || containsString(keys, operator.Recipient()) {
		t.Fatalf("first resolution keys=%v notes=%v", keys, notes)
	}

	current = changed.Recipient()
	if _, _, err := resolveRecipientKeys(newAPI(c), &c, []string{"bob@agents.test"}, false); err == nil || !strings.Contains(err.Error(), "SECURITY") {
		t.Fatalf("changed recipient key error = %v", err)
	}
	keys, notes, err = resolveRecipientKeys(newAPI(c), &c, []string{"bob@agents.test"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "re-pinned") || !containsString(keys, changed.Recipient()) {
		t.Fatalf("repin keys=%v notes=%v", keys, notes)
	}
	persisted, _ := readFileConfig()
	if got := persisted.RecipientPins[recipientPinSlot(c, "bob@agents.test")]; got != changed.Recipient() {
		t.Fatalf("persisted pin = %q", got)
	}
}

func TestSelfRecipientUsesOnlyLocallyDerivedSealedKey(t *testing.T) {
	testConfigHome(t)
	self, _ := seal.NewIdentity()
	operator, _ := seal.NewIdentity()
	var directoryCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			writeTestJSON(w, map[string]any{
				"instance": "agents.test", "email": "sender@agents.test", "pubkey": operator.Recipient(),
			})
		case "/v1/agents/sender/pubkey":
			directoryCalls.Add(1)
			writeTestJSON(w, map[string]any{"pubkey": operator.Recipient()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := clientConfig{
		URL: srv.URL, APIKey: "key", AgentID: "agt_sender",
		// A Connect/domain migration may leave the saved domain stale; the
		// stable account localpart still identifies this self-recipient.
		AgentEmail: "sender@old-instance.test", Identity: self.Secret(),
	}
	keys, notes, err := resolveRecipientKeys(newAPI(c), &c, []string{"sender@agents.test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if directoryCalls.Load() != 0 || len(notes) != 0 || len(keys) != 1 || keys[0] != self.Recipient() {
		t.Fatalf("self resolution calls=%d keys=%v notes=%v", directoryCalls.Load(), keys, notes)
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestMCPSealedSendCannotSilentlyAcceptChangedRecipientKey(t *testing.T) {
	testConfigHome(t)
	self, _ := seal.NewIdentity()
	oldRecipient, _ := seal.NewIdentity()
	newRecipient, _ := seal.NewIdentity()
	c := clientConfig{APIKey: "key", AgentID: "agt_sender", Identity: self.Secret()}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/whoami":
			writeTestJSON(w, map[string]any{"instance": "agents.test"})
		case "/v1/agents/bob/pubkey":
			writeTestJSON(w, map[string]any{"pubkey": newRecipient.Recipient()})
		default:
			t.Fatalf("MCP continued past changed key to %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c.URL = srv.URL
	c.RecipientPins = map[string]string{recipientPinSlot(c, "bob@agents.test"): oldRecipient.Recipient()}
	path := filepath.Join(t.TempDir(), "payload.txt")
	_ = os.WriteFile(path, []byte("payload"), 0o600)
	s := &mcpServer{a: newAPI(c), cfg: c}
	args, _ := json.Marshal(map[string]any{"to": []string{"bob@agents.test"}, "path": path, "seal": true})
	if _, err := s.sendFile(args); err == nil || !strings.Contains(err.Error(), "SECURITY") {
		t.Fatalf("MCP changed-key error = %v", err)
	}
}
