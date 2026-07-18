package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	serverpkg "github.com/shehryarsaroya/agenttransfer/internal/server"
)

func TestArchiveAppDirectorySafeAndDeterministic(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(name, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("index.html", "hello")
	mustWrite("assets/app.js", "console.log('ok')")
	mustWrite(".git/config", "secret history")
	mustWrite("nested/.git/objects/x", "also skipped")

	one, err := archiveAppDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(one)
	two, err := archiveAppDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(two)

	b1, _ := os.ReadFile(one)
	b2, _ := os.ReadFile(two)
	if !reflect.DeepEqual(b1, b2) {
		t.Fatal("directory archives are not deterministic")
	}

	f, err := os.Open(one)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	got := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			got[h.Name] = string(body)
		}
	}
	if got["index.html"] != "hello" || got["assets/app.js"] != "console.log('ok')" {
		t.Fatalf("archive contents = %#v", got)
	}
	for name := range got {
		if strings.Contains(name, ".git") {
			t.Fatalf("archive included git metadata %q", name)
		}
	}
}

func TestArchiveAppDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if archive, err := archiveAppDirectory(root); err == nil {
		os.Remove(archive)
		t.Fatal("symlink was packaged")
	}
}

func TestDeployAppStagesSourceAndCleansFolderRef(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantSHA := strings.Repeat("a", 64)
	var put, deploy, cleanup int
	var got appDeployRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/files/"):
			put++
			body, _ := io.ReadAll(r.Body)
			if len(body) == 0 {
				t.Error("staged archive was empty")
			}
			writeTestJSON(w, map[string]any{"sha256": wantSHA, "size": len(body)})
		case r.Method == "POST" && r.URL.Path == "/v1/apps/self/deploy":
			deploy++
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
			}
			writeTestJSON(w, map[string]any{"app": map[string]any{"status": "deploying"}, "deployment": map[string]any{"id": "dep_1"}})
		case r.Method == "DELETE" && r.URL.Path == "/v1/files/"+wantSHA:
			cleanup++
			if entry := r.URL.Query().Get("entry"); !strings.HasPrefix(entry, ".agenttransfer-deploy-") {
				t.Errorf("cleanup entry = %q", entry)
			}
			writeTestJSON(w, map[string]any{"deleted": 1})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := newAPI(clientConfig{URL: srv.URL, APIKey: "test-key"})
	raw, warning, err := deployApp(a, root, appDeployOptions{Kind: "static", Port: 8080, SPA: true})
	if err != nil {
		t.Fatal(err)
	}
	if warning != "" {
		t.Fatal(warning)
	}
	if len(raw) == 0 || put != 1 || deploy != 1 || cleanup != 1 {
		t.Fatalf("raw=%s put=%d deploy=%d cleanup=%d", raw, put, deploy, cleanup)
	}
	if got.Source != "sha256:"+wantSHA || got.Kind != "static" || !got.SPA {
		t.Fatalf("deploy request = %#v", got)
	}
}

func TestDeployAppImageSkipsFileAPI(t *testing.T) {
	var requests int
	var got appDeployRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "POST" || r.URL.Path != "/v1/apps/self/deploy" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		writeTestJSON(w, map[string]any{"app": map[string]any{"status": "deploying"}})
	}))
	defer srv.Close()
	a := newAPI(clientConfig{URL: srv.URL, APIKey: "test-key"})
	_, warning, err := deployApp(a, "", appDeployOptions{
		Image: "ghcr.io/example/app:latest", Port: 3000,
		Env: map[string]string{"MODE": "prod"}, Command: []string{"server"}, HealthPath: "/ready",
	})
	if err != nil || warning != "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}
	if requests != 1 || got.Kind != "container" || got.Source != "" || got.Port != 3000 || got.Env["MODE"] != "prod" || got.HealthPath != "/ready" {
		t.Fatalf("requests=%d request=%#v", requests, got)
	}
}

func TestDeployAppUsesLongResponseHeaderWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(75 * time.Millisecond)
		writeTestJSON(w, map[string]any{"app": map[string]any{"status": "active"}})
	}))
	defer srv.Close()

	a := newAPI(clientConfig{URL: srv.URL, APIKey: "test-key"})
	normal := a.hc.Transport.(*http.Transport).Clone()
	normal.ResponseHeaderTimeout = 10 * time.Millisecond
	a.hc.Transport = normal
	long := a.longHC.Transport.(*http.Transport).Clone()
	long.ResponseHeaderTimeout = 500 * time.Millisecond
	a.longHC.Transport = long

	// Prove the injected ordinary window is genuinely too short.
	if err := a.json(http.MethodGet, "/v1/apps/self", nil, nil); err == nil {
		t.Fatal("ordinary API request unexpectedly survived the short response-header window")
	}
	// Image deploy has no staging calls, so its only request must take the
	// dedicated long-operation client and survive the same delayed headers.
	if _, _, err := deployApp(a, "", appDeployOptions{
		Image: "ghcr.io/example/app:latest", Port: 8080, HealthPath: "/",
	}); err != nil {
		t.Fatalf("deploy did not use long response-header window: %v", err)
	}
}

func TestNormalizeAppDeployRejectsUnsafeHealthPath(t *testing.T) {
	for _, value := range []string{"relative", "//evil?x=1", "/bad#fragment", "/bad\\path", "/bad\npath"} {
		if _, err := normalizeAppDeploy("", appDeployOptions{
			Image: "example/app:1", Port: 8080, HealthPath: value,
		}); err == nil {
			t.Fatalf("health path %q was accepted", value)
		}
	}
}

func TestDeployAppCleansStagedEntryAfterRejectedDeploy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantSHA := strings.Repeat("b", 64)
	var cleanup int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/files/"):
			writeTestJSON(w, map[string]any{"sha256": wantSHA, "size": 5})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/apps/self/deploy":
			http.Error(w, `{"error":"build rejected"}`, http.StatusBadRequest)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/files/"+wantSHA:
			cleanup++
			if r.URL.Query().Get("entry") == "" {
				t.Error("precise cleanup entry missing")
			}
			writeTestJSON(w, map[string]any{"deleted": 1})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := newAPI(clientConfig{URL: srv.URL, APIKey: "test-key"})
	if _, _, err := deployApp(a, root, appDeployOptions{Kind: "static", Port: 8080}); err == nil || !strings.Contains(err.Error(), "build rejected") {
		t.Fatalf("deploy error = %v", err)
	}
	if cleanup != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanup)
	}
}

func TestDeployAppAgainstServerAndServeStaticHost(t *testing.T) {
	cfg := serverpkg.Config{
		DataDir: t.TempDir(), Metrics: "off", AppDomain: "localhost", BehindProxy: true,
	}
	cfg.ApplyDefaults()
	srv, _, err := serverpkg.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	srv.SetBaseURL(ts.URL)

	agent, key, err := srv.Store().CreateAgent("web-agent", "owner@example.test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Store().MarkOwnerVerifiedBy(agent.ID, "email"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello from hosted app"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newAPI(clientConfig{URL: ts.URL, APIKey: key})
	raw, warning, err := deployApp(a, root, appDeployOptions{Kind: "static", Port: 8080, SPA: true})
	if err != nil || warning != "" {
		t.Fatalf("deploy warning=%q err=%v", warning, err)
	}
	var deployed struct {
		App struct {
			Slug   string `json:"slug"`
			Status string `json:"status"`
		} `json:"app"`
	}
	if err := json.Unmarshal(raw, &deployed); err != nil {
		t.Fatal(err)
	}
	if deployed.App.Slug != "web-agent" || deployed.App.Status != "running" {
		t.Fatalf("deploy response = %s", raw)
	}
	files, err := srv.Store().ListFiles(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("temporary source folder ref survived deployment: %#v", files)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/nested/client/route", nil)
	req.Host = deployed.App.Slug + "." + cfg.AppDomain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello from hosted app" {
		t.Fatalf("hosted response: HTTP %d %q", resp.StatusCode, body)
	}
}

func TestExactOriginRedirectDoesNotLeakCredential(t *testing.T) {
	var leaked atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		writeTestJSON(w, map[string]any{"ok": true})
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	a := newAPI(clientConfig{URL: origin.URL, APIKey: "top-secret"})
	var out map[string]any
	if err := a.json("GET", "/v1/whoami", nil, &out); err == nil {
		t.Fatal("authenticated cross-origin redirect unexpectedly succeeded")
	}
	if leaked.Load() {
		t.Fatal("Authorization leaked across origins")
	}
}

func TestMCPUploadEscapesFilename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a?b#c.txt")
	if err := os.WriteFile(path, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantSHA := strings.Repeat("b", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v1/files/a%3Fb%23c.txt" {
			t.Errorf("escaped path = %q", got)
		}
		writeTestJSON(w, map[string]any{"sha256": wantSHA, "size": 4})
	}))
	defer srv.Close()
	s := &mcpServer{a: newAPI(clientConfig{URL: srv.URL, APIKey: "key"})}
	sha, _, _, _, err := s.upload(path, false, "", false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sha != wantSHA {
		t.Fatalf("sha = %q", sha)
	}
}

func TestMCPSendFileDecodesCCOwner(t *testing.T) {
	var ccOwner bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		ccOwner, _ = body["cc_owner"].(bool)
		writeTestJSON(w, map[string]any{"message_id": "msg_1", "delivered": []any{}})
	}))
	defer srv.Close()
	s := &mcpServer{a: newAPI(clientConfig{URL: srv.URL, APIKey: "key"})}
	if _, err := s.sendFile(json.RawMessage(`{"to":["alice@example.test"],"note":"hi","cc_owner":true}`)); err != nil {
		t.Fatal(err)
	}
	if !ccOwner {
		t.Fatal("cc_owner was not forwarded")
	}
}

func TestMCPLocalAppToolsUseAppRoutes(t *testing.T) {
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		seen[key]++
		switch key {
		case "POST /v1/apps/self/deploy":
			var req appDeployRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			if req.Image != "example/app:1" || req.Kind != "container" || req.Port != 9090 || req.HealthPath != "/healthz" {
				t.Errorf("deploy request = %#v", req)
			}
			writeTestJSON(w, map[string]any{"app": map[string]any{"status": "running"}})
		case "GET /v1/apps/self":
			writeTestJSON(w, map[string]any{"eligible": true, "app": map[string]any{"status": "running"}})
		case "GET /v1/apps/self/logs":
			if r.URL.Query().Get("tail") != "7" {
				t.Errorf("tail = %q", r.URL.Query().Get("tail"))
			}
			writeTestJSON(w, map[string]any{"logs": "one\ntwo\n", "status": "running"})
		case "POST /v1/apps/self/stop":
			writeTestJSON(w, map[string]any{"app": map[string]any{"status": "stopped"}})
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	s := &mcpServer{a: newAPI(clientConfig{URL: srv.URL, APIKey: "key"})}
	calls := []struct {
		name string
		args string
	}{
		{"deploy_app", `{"image":"example/app:1","port":9090,"health_path":"/healthz"}`},
		{"app_status", `{}`},
		{"app_logs", `{"tail":7}`},
		{"stop_app", `{}`},
	}
	for _, call := range calls {
		if _, err := s.call(call.name, json.RawMessage(call.args)); err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
	}
	for _, key := range []string{
		"POST /v1/apps/self/deploy", "GET /v1/apps/self",
		"GET /v1/apps/self/logs", "POST /v1/apps/self/stop",
	} {
		if seen[key] != 1 {
			t.Errorf("%s calls = %d", key, seen[key])
		}
	}
}

func TestMCPSpaceDownloadKeepsIndependentExpectedSHA(t *testing.T) {
	body := []byte("actual body")
	actual := sha256.Sum256(body)
	actualHex := hex.EncodeToString(actual[:])
	want := strings.Repeat("0", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sha256", actualHex)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	s := &mcpServer{a: newAPI(clientConfig{URL: srv.URL, APIKey: "key"})}
	dest := filepath.Join(t.TempDir(), "out.bin")
	if _, err := s.downloadSpaceFile("spc_1", want, dest); err == nil || !strings.Contains(err.Error(), "want "+want) {
		t.Fatalf("expected requested-sha mismatch, got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("mismatched download was committed: %v", err)
	}
}

func TestParseAppFlags(t *testing.T) {
	env, err := parseAppEnv([]string{"A=one", "EMPTY=", "A=two"})
	if err != nil || env["A"] != "two" || env["EMPTY"] != "" {
		t.Fatalf("env=%v err=%v", env, err)
	}
	if _, err := parseAppEnv([]string{"NOT-VALID=x"}); err == nil {
		t.Fatal("invalid env name accepted")
	}
	command, err := parseAppCommand([]string{`["node","server.js"]`})
	if err != nil || !reflect.DeepEqual(command, []string{"node", "server.js"}) {
		t.Fatalf("command=%v err=%v", command, err)
	}
}

func TestPrettyAppJSONRedactsEnvironmentValues(t *testing.T) {
	got := prettyRawJSON(json.RawMessage(`{"deployment":{"config":{"env":{"TOKEN":"secret","MODE":"prod"}}}}`))
	if strings.Contains(got, "secret") || strings.Contains(got, `"prod"`) {
		t.Fatalf("environment value leaked: %s", got)
	}
	if !strings.Contains(got, "TOKEN") || !strings.Contains(got, "[redacted]") {
		t.Fatalf("environment keys/redaction missing: %s", got)
	}
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
