package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	err = fn()
	_ = w.Close()
	b, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), err
}

func TestRotateKeyRejectsEnvironmentAuthBeforeRequest(t *testing.T) {
	testConfigHome(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("AGENTTRANSFER_URL", srv.URL)
	t.Setenv("AGENTTRANSFER_KEY", "old")

	if err := cmdRotateKey(nil); err == nil || !strings.Contains(err.Error(), "environment-backed") {
		t.Fatalf("rotate error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("rotation made %d request(s)", requests.Load())
	}
}

func TestRotateKeyAtomicallyPersistsAndPreservesKeyState(t *testing.T) {
	testConfigHome(t)
	id, _ := seal.NewIdentity()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/self/rotate_key" || r.Header.Get("Authorization") != "Bearer old-key" {
			t.Errorf("request = %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		writeTestJSON(w, map[string]any{"api_key": "new-key"})
	}))
	defer srv.Close()
	c := clientConfig{
		URL: srv.URL, APIKey: "old-key", AgentID: "agt_1", Identity: id.Secret(),
		RecipientPins: map[string]string{"pin": "age1example"},
	}
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return cmdRotateKey(nil) }); err != nil {
		t.Fatal(err)
	}
	got, err := readFileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.APIKey != "new-key" || got.Identity != id.Secret() || got.RecipientPins["pin"] != "age1example" {
		t.Fatalf("saved config = %+v", got)
	}
	p, _ := configPath()
	if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v err=%v", info.Mode().Perm(), err)
	}
}

func TestRotateKeyPreflightsWritableConfig(t *testing.T) {
	testConfigHome(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeTestJSON(w, map[string]any{"api_key": "new-key"})
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "old-key"}); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := cmdRotateKey(nil); err == nil || !strings.Contains(err.Error(), "not safely writable") {
		t.Fatalf("preflight error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("rotation invalidated key despite preflight failure")
	}
}

func TestDeleteSelfPreservesInactiveAccountKeyHistory(t *testing.T) {
	testConfigHome(t)
	active, _ := seal.NewIdentity()
	inactive, _ := seal.NewIdentity()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/agents/self" || r.Header.Get("Authorization") != "Bearer active-key" {
			t.Errorf("request = %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		writeTestJSON(w, map[string]any{"deleted": "active@agents.test"})
	}))
	defer srv.Close()
	activeSlot := identitySlot(srv.URL, "agt_active")
	inactiveSlot := identitySlot("https://other.test", "agt_inactive")
	c := clientConfig{
		URL: srv.URL, APIKey: "active-key", AgentID: "agt_active",
		AgentEmail: "active@agents.test", Identity: active.Secret(),
		Identities: map[string]string{inactiveSlot: inactive.Secret()},
		RecipientPins: map[string]string{
			activeSlot + "#recipient=bob@agents.test":    "active-pin",
			inactiveSlot + "#recipient=carol@other.test": "inactive-pin",
		},
	}
	if err := saveConfig(c); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return cmdDeleteSelf(nil) }); err != nil {
		t.Fatal(err)
	}
	got, err := readFileConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "" || got.APIKey != "" || got.AgentID != "" || got.Identity != "" {
		t.Fatalf("deleted login remained active: %+v", got)
	}
	if _, ok := got.Identities[activeSlot]; ok || got.Identities[inactiveSlot] != inactive.Secret() {
		t.Fatalf("identity history = %#v", got.Identities)
	}
	if _, ok := got.RecipientPins[activeSlot+"#recipient=bob@agents.test"]; ok ||
		got.RecipientPins[inactiveSlot+"#recipient=carol@other.test"] != "inactive-pin" {
		t.Fatalf("recipient pins = %#v", got.RecipientPins)
	}
}

func TestKeepReportsTierRetention(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response map[string]any
		want     string
	}{
		{"mortal", map[string]any{"name": "scratch.bin", "claimed": true, "expires_at": "2026-07-18T00:00:00Z"}, "retained until 2026-07-18T00:00:00Z"},
		{"persistent", map[string]any{"name": "kept.bin", "claimed": true}, "now persistent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testConfigHome(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeTestJSON(w, tt.response)
			}))
			defer srv.Close()
			if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
				t.Fatal(err)
			}
			out, err := captureStdout(t, func() error { return cmdKeep([]string{"sha256:abc"}) })
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, tt.want) {
				t.Fatalf("output = %q", out)
			}
		})
	}
}

func TestCardAndDirectoryShowVisibleIdentity(t *testing.T) {
	testConfigHome(t)
	cardBody := map[string]any{
		"name": "alice", "description": "renderer", "capabilities": []string{"render"},
		"public_contact": "support@alice.test",
		"verified":       map[string]any{"tier": "owner", "instance": "agents.test", "basis": "owner_record"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/directory" {
			writeTestJSON(w, map[string]any{"agents": []any{cardBody}, "count": 1})
			return
		}
		writeTestJSON(w, cardBody)
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	cardOut, err := captureStdout(t, func() error { return cmdCard([]string{"alice"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"verified: owner", "basis: owner_record", "instance: agents.test", "contact: support@alice.test"} {
		if !strings.Contains(cardOut, want) {
			t.Errorf("card output %q missing %q", cardOut, want)
		}
	}
	dirOut, err := captureStdout(t, func() error { return cmdDirectory(nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"verified: owner (owner_record)", "contact: support@alice.test"} {
		if !strings.Contains(dirOut, want) {
			t.Errorf("directory output %q missing %q", dirOut, want)
		}
	}
}

func TestCLIMsgSendsIdempotencyKey(t *testing.T) {
	testConfigHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Idempotency-Key"); got != "stable-retry" {
			t.Errorf("Idempotency-Key = %q", got)
		}
		writeTestJSON(w, map[string]any{"message_id": "msg_1", "delivered": []any{}})
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return cmdMsg([]string{"hello", "--to", "alice@agents.test", "--idempotency-key", "stable-retry"})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSendCommandsRejectInvalidIdempotencyKeyBeforeUpload(t *testing.T) {
	testConfigHome(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "request should not be made", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := strings.Repeat("x", 129)
	if err := cmdSend([]string{path, "--to", "alice@agents.test", "--idempotency-key", invalid}); err == nil || !strings.Contains(err.Error(), "1-128") {
		t.Fatalf("CLI invalid-key error = %v", err)
	}
	cfg := clientConfig{URL: srv.URL, APIKey: "key"}
	s := &mcpServer{a: newAPI(cfg), cfg: cfg}
	args, _ := json.Marshal(map[string]any{"to": []string{"alice@agents.test"}, "path": path, "idempotency_key": invalid})
	if _, err := s.sendFile(args); err == nil || !strings.Contains(err.Error(), "1-128") {
		t.Fatalf("MCP invalid-key error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("invalid keys caused %d upload/network request(s)", got)
	}
}

func TestSendCommandsHandleEntropyFailureBeforeUpload(t *testing.T) {
	testConfigHome(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "request should not be made", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	failingGenerator := func() (string, error) { return "", errors.New("entropy unavailable") }

	if err := cmdSendWithIdempotencyGenerator([]string{path, "--to", "alice@agents.test"}, failingGenerator); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("CLI entropy error = %v", err)
	}
	cfg := clientConfig{URL: srv.URL, APIKey: "key"}
	s := &mcpServer{a: newAPI(cfg), cfg: cfg}
	args, _ := json.Marshal(map[string]any{"to": []string{"alice@agents.test"}, "path": path})
	if _, err := s.sendFileWithIdempotencyGenerator(args, failingGenerator); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("MCP entropy error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("entropy failures caused %d upload/network request(s)", got)
	}
}

func TestCLIRepinRequiresSealedSend(t *testing.T) {
	if err := cmdSend([]string{"payload.bin", "--to", "alice@agents.test", "--repin"}); err == nil || !strings.Contains(err.Error(), "--repin requires --seal") {
		t.Fatalf("repin error = %v", err)
	}
}

func TestCLIEncryptedSendFailureProvidesExactRESTRecovery(t *testing.T) {
	testConfigHome(t)
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/files/"):
			_, _ = io.Copy(io.Discard, r.Body)
			writeTestJSON(w, map[string]any{"sha256": sha, "size": 123})
		case r.URL.Path == "/v1/send":
			_ = json.NewDecoder(r.Body).Decode(&sent)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":"response lost"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	if err := saveConfig(clientConfig{URL: srv.URL, APIKey: "key"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error {
		return cmdSend([]string{path, "--to", "alice@agents.test", "--encrypt", "--idempotency-key", "stable-encrypted"})
	})
	if err == nil {
		t.Fatal("encrypted send unexpectedly succeeded")
	}
	for _, want := range []string{
		"encrypted upload sha256:" + sha,
		`Idempotency-Key "stable-encrypted"`,
		`"enc_mode":"symmetric"`,
		`"file":"sha256:` + sha + `"`,
		"cannot be recreated byte-for-byte",
		"preserve the symmetric key",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if sent["file"] != "sha256:"+sha || sent["enc_mode"] != "symmetric" {
		t.Fatalf("send request = %#v", sent)
	}
}

func TestMCPSendSendsIdempotencyKey(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Idempotency-Key")
		writeTestJSON(w, map[string]any{"message_id": "msg_1", "delivered": []any{}})
	}))
	defer srv.Close()
	s := &mcpServer{a: newAPI(clientConfig{URL: srv.URL, APIKey: "key"})}
	if _, err := s.sendFile(json.RawMessage(`{"to":["alice@agents.test"],"note":"hello","idempotency_key":"mcp-retry"}`)); err != nil {
		t.Fatal(err)
	}
	if got != "mcp-retry" {
		t.Fatalf("Idempotency-Key = %q", got)
	}
}

func TestMCPRepinRequiresSealedSend(t *testing.T) {
	s := &mcpServer{}
	if _, err := s.sendFile(json.RawMessage(`{"to":["alice@agents.test"],"note":"hello","repin":true}`)); err == nil || !strings.Contains(err.Error(), "repin requires seal=true") {
		t.Fatalf("repin error = %v", err)
	}
}

func TestMCPEncryptedSendFailureRequiresExactRESTRecovery(t *testing.T) {
	const sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/files/"):
			_, _ = io.Copy(io.Discard, r.Body)
			writeTestJSON(w, map[string]any{"sha256": sha, "size": 123})
		case r.URL.Path == "/v1/send":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":"response lost"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := clientConfig{URL: srv.URL, APIKey: "key"}
	s := &mcpServer{a: newAPI(cfg), cfg: cfg}
	args, _ := json.Marshal(map[string]any{
		"to": []string{"alice@agents.test"}, "path": path, "encrypt": true,
		"idempotency_key": "mcp-encrypted",
	})
	_, err := s.sendFile(args)
	if err == nil {
		t.Fatal("encrypted MCP send unexpectedly succeeded")
	}
	for _, want := range []string{
		"encrypted upload sha256:" + sha,
		`Idempotency-Key "mcp-encrypted"`,
		`"enc_mode":"symmetric"`,
		"cannot be recreated byte-for-byte",
		"preserve the symmetric key",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestMCPDirectDownloadWithoutDigestDoesNotClaimVerification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "payload")
	}))
	defer srv.Close()
	cfg := clientConfig{URL: srv.URL, APIKey: "key"}
	out := filepath.Join(t.TempDir(), "payload.bin")
	result, err := (&mcpServer{a: newAPI(cfg), cfg: cfg}).download(srv.URL+"/payload.bin", out, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "no expected hash to verify against") || strings.Contains(result, " verified)") {
		t.Fatalf("download result = %q", result)
	}
}

func TestFormatReceiptLineHandlesShortSHA(t *testing.T) {
	got := formatReceiptLine(receipt.Receipt{Action: receipt.ActionUploaded, Actor: "a", SHA256: "abc"})
	if !strings.Contains(got, "sha256:abc") {
		t.Fatalf("line = %q", got)
	}
}
