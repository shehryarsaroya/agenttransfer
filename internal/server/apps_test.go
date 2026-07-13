package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	afmail "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

const testAppDomain = "apps.test"

func TestAppObservationFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		stop bool
	}{
		{"data measurement", &apphost.APIError{StatusCode: http.StatusUnprocessableEntity, Message: "scan timed out"}, true},
		{"runtime missing", &apphost.APIError{StatusCode: http.StatusNotFound, Message: "runtime not found"}, true},
		{"docker unavailable", &apphost.APIError{StatusCode: http.StatusBadGateway, Message: "daemon restarting"}, false},
		{"runner unavailable", errors.New("dial unix: connection refused"), false},
	} {
		if got := appObservationMustFailClosed(tc.err); got != tc.stop {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.stop)
		}
	}
}

type appTarEntry struct {
	Name     string
	Body     []byte
	Typeflag byte
	Linkname string
}

func makeAppTar(t *testing.T, entries ...appTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		typ := entry.Typeflag
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{
			Name: entry.Name, Mode: 0o644, Typeflag: typ, Linkname: entry.Linkname,
		}
		if typ == tar.TypeReg || typ == tar.TypeRegA {
			h.Size = int64(len(entry.Body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header %q: %v", entry.Name, err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(entry.Body); err != nil {
				t.Fatalf("tar body %q: %v", entry.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newAppTestEnv(t *testing.T, quota int64) *env {
	t.Helper()
	return newEnvCfg(t, Config{
		AppDomain:       testAppDomain,
		AppStorageQuota: quota,
		AppBundleSize:   4 << 20,
		BehindProxy:     true,
	})
}

func TestServerPrecreatesAppRootBeforeRunner(t *testing.T) {
	appRoot := filepath.Join(t.TempDir(), "shared-app-root")
	if err := os.MkdirAll(filepath.Join(appRoot, "contexts", "stale-build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(appRoot, "data", "durable-app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appRoot, "data", "durable-app", "keep"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvCfg(t, Config{
		AppDomain: testAppDomain, AppRoot: appRoot, BehindProxy: true,
	})
	if e.srv.cfg.AppRoot != appRoot {
		t.Fatalf("APP_ROOT = %q, want %q", e.srv.cfg.AppRoot, appRoot)
	}
	info, err := os.Stat(appRoot)
	if err != nil || !info.IsDir() {
		t.Fatalf("public service did not precreate APP_ROOT: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(filepath.Join(appRoot, "contexts")); !os.IsNotExist(err) {
		t.Fatalf("stale build contexts survived startup: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(appRoot, "data", "durable-app", "keep")); err != nil || string(body) != "state" {
		t.Fatalf("startup context cleanup touched persistent data: %q err=%v", body, err)
	}
}

func humanVerifyAgent(t *testing.T, e *env, key, owner string) store.Agent {
	t.Helper()
	a, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetOwnerPending(a.ID, owner); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.MarkOwnerVerifiedBy(a.ID, "email"); err != nil {
		t.Fatal(err)
	}
	a, err = e.srv.st.AgentByID(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HumanVerified() {
		t.Fatalf("test agent was not human verified: %+v", a)
	}
	return a
}

func uploadAppArchive(t *testing.T, e *env, key, name string, archive []byte) {
	t.Helper()
	e.upload(key, name, archive, "")
}

func deployStaticApp(t *testing.T, e *env, key, source string, spa bool) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"kind": "static", "source": source, "spa": spa,
	})
	resp, data := e.do(http.MethodPost, "/v1/apps/self/deploy", key, bytes.NewReader(body), "application/json")
	return resp.StatusCode, data
}

func appHostRequest(t *testing.T, e *env, method, host, path string) (*http.Response, []byte) {
	return appHostRequestBody(t, e, method, host, path, nil)
}

func appHostRequestBody(t *testing.T, e *env, method, host, path string, requestBody io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, responseBody
}

func TestContainerAppProxyPreservesHTTPMethodsAndCanonicalForwarding(t *testing.T) {
	var gotMethod, gotPath, gotBody, gotHost, gotForwarded, gotXFF, gotXFHost, gotXFProto string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.RequestURI()
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotHost = r.Host
		gotForwarded = r.Header.Get("Forwarded")
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXFHost = r.Header.Get("X-Forwarded-Host")
		gotXFProto = r.Header.Get("X-Forwarded-Proto")
		w.Header().Set("X-App", "yes")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	e := newAppTestEnv(t, 1<<20)
	_, key := e.createAgent("method-api")
	agent := humanVerifyAgent(t, e, key, "api-owner@example.com")
	app, err := e.srv.st.EnsureApp(agent.ID, agent.Name)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := e.srv.st.StageContainerDeployment(agent.ID, "", 0, `{}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	app, _, err = e.srv.st.SetAppRuntime(agent.ID, deployment.ID, "aaaaaaaaaaaa", upstream.URL, "example/api:1", 8080, nil)
	if err != nil {
		t.Fatal(err)
	}

	host := app.Slug + "." + testAppDomain
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/v1/items?dry=1", strings.NewReader(`{"name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Forwarded", "for=attacker;proto=https;host=evil.example")
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https, http")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted || string(body) != "proxied" || resp.Header.Get("X-App") != "yes" {
		t.Fatalf("proxy response: HTTP %d headers=%v body=%q", resp.StatusCode, resp.Header, body)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/items?dry=1" || gotBody != `{"name":"test"}` {
		t.Fatalf("upstream request method=%q path=%q body=%q", gotMethod, gotPath, gotBody)
	}
	if gotHost != host || gotForwarded != "" || gotXFHost != host || gotXFProto != "http" || gotXFF != "127.0.0.1" {
		t.Fatalf("forwarding host=%q Forwarded=%q XFF=%q XFHost=%q XFProto=%q", gotHost, gotForwarded, gotXFF, gotXFHost, gotXFProto)
	}
}

func TestAppHostingRequiresHumanEmailVerification(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	var signup struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	code := e.doJSON(http.MethodPost, "/v1/agents", e.admin, map[string]any{
		"name": "operator-vouched", "owner_email": "owner@example.com",
	}, &signup)
	if code != http.StatusCreated {
		t.Fatalf("signup: HTTP %d", code)
	}
	agent, err := e.srv.st.AgentByID(signup.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if !agent.OwnerVerified || agent.OwnerVerificationMethod != "operator" || agent.HumanVerified() {
		t.Fatalf("admin-created identity provenance is wrong: %+v", agent)
	}

	var gated struct {
		Eligible bool   `json:"eligible"`
		Reason   string `json:"reason"`
	}
	if code := e.doJSON(http.MethodGet, "/v1/apps/self", signup.APIKey, nil, &gated); code != http.StatusOK {
		t.Fatalf("status: HTTP %d", code)
	}
	if gated.Eligible || !strings.Contains(gated.Reason, "human owner") {
		t.Fatalf("operator verification unlocked hosting: %+v", gated)
	}
	if _, err := e.srv.st.AppByAgentID(agent.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ineligible status call allocated an app: %v", err)
	}
	if code := e.doJSON(http.MethodPost, "/v1/apps/self/deploy", signup.APIKey,
		map[string]any{"kind": "static", "source": "missing.tar.gz"}, nil); code != http.StatusForbidden {
		t.Fatalf("operator-verified deploy: HTTP %d, want 403", code)
	}

	if err := e.srv.st.MarkOwnerVerifiedBy(agent.ID, "email"); err != nil {
		t.Fatal(err)
	}
	var allowed struct {
		Eligible bool `json:"eligible"`
		App      struct {
			Slug   string `json:"slug"`
			URL    string `json:"url"`
			Status string `json:"status"`
		} `json:"app"`
	}
	if code := e.doJSON(http.MethodGet, "/v1/apps/self", signup.APIKey, nil, &allowed); code != http.StatusOK {
		t.Fatalf("verified status: HTTP %d", code)
	}
	if !allowed.Eligible || allowed.App.Slug != "operator-vouched" || allowed.App.URL != "https://operator-vouched."+testAppDomain {
		t.Fatalf("email verification did not unlock canonical app identity: %+v", allowed)
	}
}

func TestStaticAppDeployAndExactHostLifecycle(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("site-agent")
	agent := humanVerifyAgent(t, e, key, "site-owner@example.com")
	indexBody := []byte("<!doctype html><h1>release one</h1>")
	cssBody := []byte("body { color: rebeccapurple; }")
	archive := makeAppTar(t,
		appTarEntry{Name: "index.html", Body: indexBody},
		appTarEntry{Name: "assets/site.css", Body: cssBody},
	)
	uploadAppArchive(t, e, key, "site-v1.tar.gz", archive)
	code, data := deployStaticApp(t, e, key, "site-v1.tar.gz", true)
	if code != http.StatusCreated {
		t.Fatalf("deploy: HTTP %d: %s", code, data)
	}
	app, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != store.AppStatusRunning || app.Kind != store.AppKindStatic || app.ActiveDeploymentID == "" {
		t.Fatalf("bad active app metadata: %+v", app)
	}
	host := app.Slug + "." + testAppDomain

	resp, body := appHostRequest(t, e, http.MethodGet, host, "/")
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, indexBody) {
		t.Fatalf("index: HTTP %d body=%q", resp.StatusCode, body)
	}
	wantIndexSHA := sha256.Sum256(indexBody)
	if got, want := resp.Header.Get("ETag"), `"sha256-`+hex.EncodeToString(wantIndexSHA[:])+`"`; got != want {
		t.Fatalf("index ETag=%q, want %q", got, want)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("index MIME=%q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("index cache=%q", got)
	}

	resp, body = appHostRequest(t, e, http.MethodGet, host, "/assets/site.css")
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, cssBody) {
		t.Fatalf("asset: HTTP %d body=%q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Fatalf("asset MIME=%q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("asset cache=%q", got)
	}

	resp, body = appHostRequest(t, e, http.MethodHead, strings.ToUpper(host)+":443", "/assets/site.css")
	if resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD: HTTP %d body bytes=%d", resp.StatusCode, len(body))
	}
	if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(len(cssBody)); got != want {
		t.Fatalf("HEAD Content-Length=%q, want %s", got, want)
	}

	resp, body = appHostRequest(t, e, http.MethodGet, host, "/dashboard/settings")
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, indexBody) {
		t.Fatalf("SPA fallback: HTTP %d body=%q", resp.StatusCode, body)
	}
	if resp, _ := appHostRequest(t, e, http.MethodGet, host, "/missing.js"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("SPA served missing asset: HTTP %d", resp.StatusCode)
	}
	// A nested or sibling hostname must never borrow this site's contents.
	if resp, body := appHostRequest(t, e, http.MethodGet, "other."+testAppDomain, "/assets/site.css"); resp.StatusCode != http.StatusNotFound || bytes.Equal(body, cssBody) {
		t.Fatalf("wrong host reached site: HTTP %d body=%q", resp.StatusCode, body)
	}
	if resp, body := appHostRequest(t, e, http.MethodGet, "nested."+host, "/assets/site.css"); resp.StatusCode == http.StatusOK && bytes.Equal(body, cssBody) {
		t.Fatalf("nested host reached site: HTTP %d body=%q", resp.StatusCode, body)
	}

	// A rejected replacement must leave the old deployment pointer and bytes
	// untouched and publicly live.
	beforeID := app.ActiveDeploymentID
	bad := makeAppTar(t, appTarEntry{Name: "about.html", Body: []byte("not an index")})
	uploadAppArchive(t, e, key, "site-bad.tar.gz", bad)
	if code, _ := deployStaticApp(t, e, key, "site-bad.tar.gz", false); code != http.StatusBadRequest {
		t.Fatalf("missing-index replacement: HTTP %d, want 400", code)
	}
	after, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil || after.ActiveDeploymentID != beforeID || after.Status != store.AppStatusRunning {
		t.Fatalf("failed replacement changed active app: before=%s after=%+v err=%v", beforeID, after, err)
	}
	if resp, body := appHostRequest(t, e, http.MethodGet, host, "/"); resp.StatusCode != http.StatusOK || !bytes.Equal(body, indexBody) {
		t.Fatalf("old release not live after failed replacement: HTTP %d body=%q", resp.StatusCode, body)
	}

	if code := e.doJSON(http.MethodPost, "/v1/apps/self/stop", key, nil, nil); code != http.StatusOK {
		t.Fatalf("stop: HTTP %d", code)
	}
	if resp, _ := appHostRequest(t, e, http.MethodGet, host, "/"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stopped app remained public: HTTP %d", resp.StatusCode)
	}
	if code := e.doJSON(http.MethodDelete, "/v1/apps/self?purge_data=true", key, nil, nil); code != http.StatusOK {
		t.Fatalf("purge static-only app without runner: HTTP %d", code)
	}
	if _, err := e.srv.st.AppByAgentID(agent.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("purged static app still exists: %v", err)
	}
}

func TestStaticAppRejectsMaliciousArchives(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	_, key := e.createAgent("archive-guard")
	agent := humanVerifyAgent(t, e, key, "archive-owner@example.com")

	tests := []struct {
		name    string
		entries []appTarEntry
		want    string
	}{
		{
			name: "traversal",
			entries: []appTarEntry{
				{Name: "index.html", Body: []byte("ok")},
				{Name: "../escape.txt", Body: []byte("escape")},
			},
			want: "path",
		},
		{
			name: "symlink",
			entries: []appTarEntry{
				{Name: "index.html", Body: []byte("ok")},
				{Name: "passwd", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
			},
			want: "unsupported archive entry type",
		},
		{
			name: "duplicate",
			entries: []appTarEntry{
				{Name: "index.html", Body: []byte("one")},
				{Name: "index.html", Body: []byte("two")},
			},
			want: "duplicate path",
		},
		{
			name:    "missing-index",
			entries: []appTarEntry{{Name: "about.html", Body: []byte("about")}},
			want:    "needs index.html",
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := "malicious-" + string(rune('a'+i)) + ".tar.gz"
			uploadAppArchive(t, e, key, name, makeAppTar(t, tc.entries...))
			code, body := deployStaticApp(t, e, key, name, false)
			if code != http.StatusBadRequest {
				t.Fatalf("HTTP %d: %s", code, body)
			}
			if tc.want != "" && !strings.Contains(strings.ToLower(string(body)), strings.ToLower(tc.want)) {
				t.Fatalf("response %q does not explain %q", body, tc.want)
			}
		})
	}
	if app, err := e.srv.st.AppByAgentID(agent.ID); err != nil || app.ActiveDeploymentID != "" || app.Status == store.AppStatusRunning {
		t.Fatalf("rejected archives activated an app: %+v err=%v", app, err)
	}
}

func TestStaticAppRejectsExpandedReleaseOverQuota(t *testing.T) {
	e := newAppTestEnv(t, 128)
	_, key := e.createAgent("expansion-guard")
	humanVerifyAgent(t, e, key, "expansion-owner@example.com")
	archive := makeAppTar(t,
		appTarEntry{Name: "index.html", Body: bytes.Repeat([]byte("x"), 129)},
	)
	uploadAppArchive(t, e, key, "too-large-expanded.tar.gz", archive)
	code, body := deployStaticApp(t, e, key, "too-large-expanded.tar.gz", false)
	if code != http.StatusBadRequest || !strings.Contains(strings.ToLower(string(body)), "expanded release") {
		t.Fatalf("expansion quota: HTTP %d body=%s", code, body)
	}
}

func TestAppArchivePreservesDiskReserveSentinel(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	_, key := e.createAgent("archive-disk-guard")
	agent := humanVerifyAgent(t, e, key, "disk-owner@example.com")
	uploadAppArchive(t, e, key, "site.tar.gz", makeAppTar(t,
		appTarEntry{Name: "index.html", Body: []byte("hello")},
	))
	source, err := e.srv.st.FileByName(agent.ID, "site.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Store().SetDiskReserve(1 << 62)
	_, err = e.srv.readAppArchive(source, 1<<20)
	if !errors.Is(err, store.ErrDiskReserve) {
		t.Fatalf("archive disk guard error = %v, want ErrDiskReserve", err)
	}
}

func TestBuildContextStopsAtDiskReserveAndCleansPartialState(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	sha, size, err := e.srv.st.PutBlob(strings.NewReader("FROM scratch\n"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Store().SetDiskReserve(1 << 62)
	app := store.App{ID: "app_context_guard"}
	deployment := store.AppDeployment{ID: "dep_context_guard"}
	_, err = e.srv.materializeAppContext(app, deployment, []store.AppFileSpec{{
		Path: "Dockerfile", SHA256: sha, Size: size,
	}})
	if !errors.Is(err, store.ErrDiskReserve) {
		t.Fatalf("materialize error = %v, want ErrDiskReserve", err)
	}
	contextDir := filepath.Join(e.srv.cfg.AppRoot, "contexts", app.ID, deployment.ID)
	if _, statErr := os.Stat(contextDir); !os.IsNotExist(statErr) {
		t.Fatalf("partial context survived reserve failure: %v", statErr)
	}
}

func TestAppURLSlugForUnsafeAndPersonAgentNames(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

	_, unsafeKey := e.createAgent("under_score")
	unsafeAgent := humanVerifyAgent(t, e, unsafeKey, "unsafe-owner@example.com")
	person, err := e.srv.st.CreatePerson("fleet_owner", "fleet-owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	personAgent, personKey, err := e.srv.st.CreateAgentForPerson(person, "lap_top")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.MarkOwnerVerifiedBy(personAgent.ID, "email"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, key, prefix string
		agentID           string
	}{
		{name: "underscore", key: unsafeKey, prefix: "under-score-", agentID: unsafeAgent.ID},
		{name: "person-plus", key: personKey, prefix: "fleet-owner-lap-top-", agentID: personAgent.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out struct {
				Eligible bool `json:"eligible"`
				App      struct {
					Slug string `json:"slug"`
					URL  string `json:"url"`
				} `json:"app"`
			}
			if code := e.doJSON(http.MethodGet, "/v1/apps/self", tc.key, nil, &out); code != http.StatusOK {
				t.Fatalf("status: HTTP %d", code)
			}
			if !out.Eligible || !strings.HasPrefix(out.App.Slug, tc.prefix) || !dnsLabel.MatchString(out.App.Slug) {
				t.Fatalf("unsafe name did not get a suffixed DNS slug: %+v", out)
			}
			if out.App.URL != "https://"+out.App.Slug+"."+testAppDomain {
				t.Fatalf("URL=%q slug=%q", out.App.URL, out.App.Slug)
			}
			app, err := e.srv.st.AppByAgentID(tc.agentID)
			if err != nil || app.Slug != out.App.Slug {
				t.Fatalf("slug was not durable: %+v err=%v", app, err)
			}
		})
	}
}

func verificationTokenFromSink(t *testing.T, msg sinkMsg) string {
	t.Helper()
	in, err := afmail.ParseInbound(bytes.NewReader(msg.Data), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`/verify\?t=([A-Za-z0-9_-]+)`)
	m := re.FindStringSubmatch(in.Text)
	if len(m) != 2 {
		t.Fatalf("verification token missing from message text %q", in.Text)
	}
	return m[1]
}

func TestOwnerAttachmentInvalidatesOldTokensAndRecordsEmailProof(t *testing.T) {
	addr, sink := newSMTPSink(t)
	e := newEnvCfg(t, Config{
		Domain:      "agents.test",
		BehindProxy: true,
		HTTPAddr:    ":8080",
		Outbound:    "smtp://" + addr,
		AppDomain:   testAppDomain,
	})
	var signup struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	if code := e.doJSON(http.MethodPost, "/v1/agents", e.admin, map[string]string{"name": "attach-owner"}, &signup); code != http.StatusCreated {
		t.Fatalf("signup: HTTP %d", code)
	}
	oldToken, err := e.srv.st.CreateVerifyToken(signup.AgentID)
	if err != nil {
		t.Fatal(err)
	}

	if code := e.doJSON(http.MethodPost, "/v1/agents/self/owner", signup.APIKey,
		map[string]string{"email": "first-owner@example.com"}, nil); code != http.StatusAccepted {
		t.Fatalf("first owner attach: HTTP %d", code)
	}
	msgs := sink.all()
	if len(msgs) != 1 {
		t.Fatalf("verification messages=%d, want 1", len(msgs))
	}
	firstToken := verificationTokenFromSink(t, msgs[0])
	if resp, _ := e.do(http.MethodPost, "/verify?t="+oldToken, "", nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("pre-attachment token remained valid: HTTP %d", resp.StatusCode)
	}

	if code := e.doJSON(http.MethodPost, "/v1/agents/self/owner", signup.APIKey,
		map[string]string{"email": "second-owner@example.com"}, nil); code != http.StatusAccepted {
		t.Fatalf("second owner attach: HTTP %d", code)
	}
	msgs = sink.all()
	if len(msgs) != 2 {
		t.Fatalf("verification messages=%d, want 2", len(msgs))
	}
	secondToken := verificationTokenFromSink(t, msgs[1])
	if resp, _ := e.do(http.MethodPost, "/verify?t="+firstToken, "", nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("first-owner token remained valid after replacement: HTTP %d", resp.StatusCode)
	}
	if resp, body := e.do(http.MethodPost, "/verify?t="+secondToken, "", nil, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("second-owner verification: HTTP %d body=%s", resp.StatusCode, body)
	}

	agent, err := e.srv.st.AgentByID(signup.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if agent.OwnerEmail != "second-owner@example.com" || agent.OwnerVerificationMethod != "email" || !agent.HumanVerified() {
		t.Fatalf("owner verification provenance: %+v", agent)
	}
	var status struct {
		Eligible bool `json:"eligible"`
	}
	if code := e.doJSON(http.MethodGet, "/v1/apps/self", signup.APIKey, nil, &status); code != http.StatusOK || !status.Eligible {
		t.Fatalf("email proof did not unlock apps: HTTP %d response=%+v", code, status)
	}
	if code := e.doJSON(http.MethodPost, "/v1/agents/self/owner", signup.APIKey,
		map[string]string{"email": "third-owner@example.com"}, nil); code != http.StatusConflict {
		t.Fatalf("verified owner replacement: HTTP %d, want 409", code)
	}
}
