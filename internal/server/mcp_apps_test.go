package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

type mcpRunnerCapture struct {
	mu                  sync.Mutex
	build               apphost.BuildRequest
	deploy              apphost.DeployRequest
	logTail             string
	buildCalled         bool
	stopCalled          bool
	removeCalled        bool
	removeImageCalled   bool
	removedImage        string
	startCalled         bool
	failDeploy          bool
	failStop            bool
	deployCount         int
	runtimeID           string
	upstream            string
	running             bool
	dataBytes           int64
	removed             bool
	reconcileCalled     bool
	failReconcileUnsafe bool
	containerReady      bool
	containerState      string
}

func attachMCPFakeRunner(t *testing.T, e *env, logOutput string) *mcpRunnerCapture {
	t.Helper()
	socketDir, err := os.MkdirTemp("", "at-mcp-runner-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "runner.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("runner-token-", 3)
	capture := &mcpRunnerCapture{containerReady: true, containerState: "ready"}
	runtimeID := "aaaaaaaaaaaa"
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(healthServer.Close)
	capture.runtimeID = runtimeID
	capture.upstream = healthServer.URL
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		capture.mu.Lock()
		ready, state := capture.containerReady, capture.containerState
		capture.mu.Unlock()
		write(w, map[string]any{"ok": true, "container_ready": ready, "container_state": state})
	})
	mux.HandleFunc("POST /v1/build", func(w http.ResponseWriter, r *http.Request) {
		var req apphost.BuildRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		image := "agenttransfer-app/" + req.AppID + ":" + req.ReleaseID
		capture.mu.Lock()
		capture.build = req
		capture.buildCalled = true
		capture.mu.Unlock()
		write(w, apphost.BuildResult{AppID: req.AppID, ReleaseID: req.ReleaseID, Image: image})
	})
	mux.HandleFunc("POST /v1/apps/{id}/images/{release}/remove", func(w http.ResponseWriter, r *http.Request) {
		appID, releaseID := r.PathValue("id"), r.PathValue("release")
		image := "agenttransfer-app/" + appID + ":" + releaseID
		capture.mu.Lock()
		capture.removeImageCalled = true
		capture.removedImage = image
		capture.mu.Unlock()
		write(w, apphost.RemoveImageResult{AppID: appID, ReleaseID: releaseID, Image: image, Removed: true})
	})
	mux.HandleFunc("POST /v1/deploy", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req apphost.DeployRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		capture.mu.Lock()
		capture.deploy = req
		capture.deployCount++
		failDeploy := capture.failDeploy
		capture.mu.Unlock()
		if failDeploy {
			w.WriteHeader(http.StatusBadGateway)
			write(w, map[string]string{"error": "simulated replacement failure"})
			return
		}
		capture.mu.Lock()
		capture.running = true
		capture.removed = false
		capture.mu.Unlock()
		write(w, apphost.DeployResponse{
			AppID: req.AppID, ReleaseID: req.ReleaseID, RuntimeID: runtimeID,
			ContainerName: "agenttransfer-test", Upstream: healthServer.URL,
			Image: req.Image, Healthy: true,
		})
	})
	mux.HandleFunc("GET /v1/runtimes/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.logTail = r.URL.Query().Get("tail")
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.LogsResult{AppID: deploy.AppID, Lines: 7, Output: logOutput})
	})
	mux.HandleFunc("GET /v1/runtimes/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		deploy := capture.deploy
		running := capture.running
		dataBytes := capture.dataBytes
		capture.mu.Unlock()
		state := "exited"
		if running {
			state = "running"
		}
		write(w, apphost.AppStatus{
			AppID: deploy.AppID, ReleaseID: deploy.ReleaseID, Image: deploy.Image,
			ContainerID: runtimeID, State: state, Running: running, URL: healthServer.URL, DataBytes: dataBytes,
		})
	})
	mux.HandleFunc("GET /v1/runtimes/{id}/route", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		deploy := capture.deploy
		running := capture.running
		capture.mu.Unlock()
		state := "exited"
		if running {
			state = "running"
		}
		write(w, apphost.AppStatus{
			AppID: deploy.AppID, ReleaseID: deploy.ReleaseID, Image: deploy.Image,
			ContainerID: runtimeID, State: state, Running: running, URL: healthServer.URL,
		})
	})
	mux.HandleFunc("GET /v1/apps/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		deploy := capture.deploy
		running := capture.running
		removed := capture.removed
		capture.mu.Unlock()
		if removed {
			w.WriteHeader(http.StatusNotFound)
			write(w, map[string]string{"error": "app runtime not found"})
			return
		}
		state := "exited"
		if running {
			state = "running"
		}
		write(w, apphost.AppStatus{
			AppID: deploy.AppID, ReleaseID: deploy.ReleaseID, Image: deploy.Image,
			ContainerID: runtimeID, State: state, Running: running, URL: healthServer.URL,
		})
	})
	mux.HandleFunc("POST /v1/runtimes/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.stopCalled = true
		capture.running = false
		deploy := capture.deploy
		failStop := capture.failStop
		capture.mu.Unlock()
		if failStop {
			w.WriteHeader(http.StatusBadGateway)
			write(w, map[string]string{"error": "simulated ambiguous stop failure"})
			return
		}
		write(w, apphost.StopResult{AppID: deploy.AppID, RuntimeID: runtimeID, Stopped: true})
	})
	mux.HandleFunc("POST /v1/runtimes/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.startCalled = true
		capture.running = true
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.AppStatus{
			AppID: deploy.AppID, ReleaseID: deploy.ReleaseID, Image: deploy.Image,
			ContainerID: runtimeID, State: "running", Running: true, URL: healthServer.URL,
		})
	})
	mux.HandleFunc("POST /v1/apps/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.stopCalled = true
		capture.running = false
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.StopResult{AppID: deploy.AppID, Stopped: true, StoppedIDs: []string{runtimeID}})
	})
	mux.HandleFunc("POST /v1/apps/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.removeCalled = true
		capture.removed = true
		capture.running = false
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.RemoveAppResult{AppID: deploy.AppID, RemovedRuntimes: 1})
	})
	mux.HandleFunc("POST /v1/apps/{id}/reconcile", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.reconcileCalled = true
		failUnsafe := capture.failReconcileUnsafe
		deploy := capture.deploy
		capture.mu.Unlock()
		if failUnsafe {
			w.WriteHeader(http.StatusBadGateway)
			write(w, map[string]string{"error": "refusing to manage unsafe app network"})
			return
		}
		write(w, apphost.ReconcileResult{AppID: deploy.AppID, KeptRuntimeID: runtimeID})
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() {
		_ = httpSrv.Shutdown(context.Background())
		_ = ln.Close()
		_ = os.Remove(socket)
	})
	client, err := apphost.NewClient(apphost.ClientConfig{
		SocketPath: socket, AuthToken: token, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.appRunner = client
	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{
		RunnerConfigured: true, RunnerReady: true, WildcardDNSReady: true, CheckedAt: time.Now(),
	}
	e.srv.appReadyMu.Unlock()
	t.Cleanup(client.Close)
	return capture
}

func hostedMCPRPC(t *testing.T, e *env, key, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	resp, data := e.do(http.MethodPost, "/mcp", key, bytes.NewReader(body), "application/json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp %s: HTTP %d %s", method, resp.StatusCode, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["error"] != nil {
		t.Fatalf("mcp %s RPC error: %v", method, out["error"])
	}
	result, _ := out["result"].(map[string]any)
	return result
}

func hostedMCPTool(t *testing.T, e *env, key, name string, args any) (text string, isError bool) {
	t.Helper()
	result := hostedMCPRPC(t, e, key, "tools/call", map[string]any{"name": name, "arguments": args})
	isError, _ = result["isError"].(bool)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("tool %s returned no content: %v", name, result)
	}
	block, _ := content[0].(map[string]any)
	text, _ = block["text"].(string)
	return text, isError
}

func TestHostedMCPAppToolsGateDeployAndLifecycle(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("mcp-app")

	tools := hostedMCPRPC(t, e, key, "tools/list", map[string]any{})
	list, _ := tools["tools"].([]any)
	names := map[string]bool{}
	for _, item := range list {
		tool, _ := item.(map[string]any)
		name, _ := tool["name"].(string)
		names[name] = true
	}
	for _, want := range []string{"app_status", "deploy_app_image", "app_logs", "stop_app"} {
		if !names[want] {
			t.Fatalf("hosted tools/list missing %q", want)
		}
	}

	status, failed := hostedMCPTool(t, e, key, "app_status", map[string]any{})
	if failed || !strings.Contains(status, `"eligible": false`) {
		t.Fatalf("unverified app_status failed=%v: %s", failed, status)
	}
	blocked, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{"image": "example/app:1"})
	if !failed || !strings.Contains(blocked, "human owner") {
		t.Fatalf("unverified deploy failed=%v: %s", failed, blocked)
	}
	local, failed := hostedMCPTool(t, e, key, "deploy_app", map[string]any{"path": "/tmp/site"})
	if !failed || !strings.Contains(local, "local stdio bridge") {
		t.Fatalf("hosted source deploy explanation failed=%v: %s", failed, local)
	}

	humanVerifyAgent(t, e, key, "mcp-owner@example.test")
	logs := strings.Repeat("x", (256<<10)+4096)
	capture := attachMCPFakeRunner(t, e, logs)
	deployed, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "port": 9090,
		"env":     map[string]string{"TOKEN": "super-secret", "MODE": "prod"},
		"command": []string{"serve", "--http"}, "health_path": "/healthz",
	})
	if failed {
		t.Fatalf("verified deploy failed: %s", deployed)
	}
	if strings.Contains(deployed, "super-secret") || strings.Contains(deployed, `"prod"`) {
		t.Fatalf("deploy response exposed env values: %s", deployed)
	}
	if !strings.Contains(deployed, "TOKEN") || !strings.Contains(deployed, "running") {
		t.Fatalf("deploy response missing safe app details: %s", deployed)
	}
	capture.mu.Lock()
	gotDeploy := capture.deploy
	capture.mu.Unlock()
	if gotDeploy.Image != "example/app:1" || gotDeploy.ContainerPort != 9090 ||
		gotDeploy.Env["TOKEN"] != "super-secret" || gotDeploy.HealthPath != "/healthz" {
		t.Fatalf("runner deploy request = %#v", gotDeploy)
	}
	// Revoking the human-email proof gates operational tools too; merely owning
	// a still-running app must not bypass the same eligibility rule as deploy.
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetOwnerPending(agent.ID, "mcp-owner@example.test"); err != nil {
		t.Fatal(err)
	}
	statusAfterRevoke, failed := hostedMCPTool(t, e, key, "app_status", map[string]any{})
	if failed || !strings.Contains(statusAfterRevoke, `"eligible": false`) || !strings.Contains(statusAfterRevoke, `"status": "running"`) {
		t.Fatalf("revoked status failed=%v: %s", failed, statusAfterRevoke)
	}

	logText, failed := hostedMCPTool(t, e, key, "app_logs", map[string]any{"tail": 7})
	if failed || !strings.Contains(logText, `"truncated": true`) || len(logText) > 270<<10 {
		t.Fatalf("bounded logs failed=%v bytes=%d: %.200s", failed, len(logText), logText)
	}
	capture.mu.Lock()
	gotTail := capture.logTail
	capture.mu.Unlock()
	if gotTail != "7" {
		t.Fatalf("runner log tail = %q", gotTail)
	}

	stopped, failed := hostedMCPTool(t, e, key, "stop_app", map[string]any{})
	if failed || !strings.Contains(stopped, "stopped") {
		t.Fatalf("stop failed=%v: %s", failed, stopped)
	}
	capture.mu.Lock()
	stopCalled := capture.stopCalled
	capture.mu.Unlock()
	if !stopCalled {
		t.Fatal("runner stop was not called after eligibility loss")
	}

	appBeforeDelete, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = e.srv.appProxySlot(appBeforeDelete.ID)
	if code := e.doJSON(http.MethodDelete, "/v1/apps/self", key, nil, nil); code != http.StatusOK {
		t.Fatalf("delete app: HTTP %d", code)
	}
	capture.mu.Lock()
	removeCalled := capture.removeCalled
	capture.mu.Unlock()
	if !removeCalled {
		t.Fatal("app deletion orphaned its stopped runtime")
	}
	if _, ok := e.srv.appProxyAppSlots.Load(appBeforeDelete.ID); ok {
		t.Fatal("app deletion retained its per-app proxy semaphore")
	}
}

func TestFailedContainerReplacementRestoresPreviousHealthyRuntime(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("restore-app")
	agent := humanVerifyAgent(t, e, key, "restore-owner@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")

	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "health_path": "/healthz",
	}); failed {
		t.Fatalf("initial deploy failed: %s", text)
	}
	capture.mu.Lock()
	capture.failDeploy = true
	capture.mu.Unlock()
	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:2", "health_path": "/healthz",
	}); !failed || !strings.Contains(text, "simulated replacement failure") {
		t.Fatalf("replacement result failed=%v: %s", failed, text)
	}

	capture.mu.Lock()
	startCalled := capture.startCalled
	reconcileCalled := capture.reconcileCalled
	runtimeID := capture.runtimeID
	upstream := capture.upstream
	capture.mu.Unlock()
	if !startCalled {
		t.Fatal("failed replacement did not restart the previous runtime")
	}
	if !reconcileCalled {
		t.Fatal("ambiguous replacement failure did not reconcile unknown runtimes before restoring the old one")
	}
	app, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != store.AppStatusRunning || app.RuntimeID != runtimeID || app.Upstream != upstream {
		t.Fatalf("previous runtime was not restored in routing state: %+v", app)
	}
	resp, err := http.Get(app.Upstream + "/healthz")
	if err != nil {
		t.Fatalf("restored upstream is not serving: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("restored upstream health HTTP %d", resp.StatusCode)
	}
}

func TestJanitorRestartsDesiredRuntimeAfterInterruptedReplacement(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("crash-recovery-app")
	agent := humanVerifyAgent(t, e, key, "crash-owner@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")
	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "health_path": "/healthz",
	}); failed {
		t.Fatalf("initial deploy failed: %s", text)
	}
	capture.mu.Lock()
	capture.running = false // server died after draining old, before DB switch
	capture.startCalled = false
	capture.mu.Unlock()

	e.srv.reconcileAppQuota(agent.ID)
	capture.mu.Lock()
	started, running := capture.startCalled, capture.running
	capture.mu.Unlock()
	if !started || !running {
		t.Fatalf("janitor did not restore desired runtime: start=%v running=%v", started, running)
	}
	app, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil || app.Status != store.AppStatusRunning {
		t.Fatalf("restored app state = %+v, %v", app, err)
	}
}

func TestWatchdogKeepsStaticReleaseAfterContainerHistory(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("static-after-container")
	agent := humanVerifyAgent(t, e, key, "static-after-container@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")

	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "health_path": "/healthz",
	}); failed {
		t.Fatalf("container deploy failed: %s", text)
	}
	archive := makeAppTar(t, appTarEntry{Name: "index.html", Body: []byte("static release")})
	uploadAppArchive(t, e, key, "static.tar.gz", archive)
	if code, body := deployStaticApp(t, e, key, "static.tar.gz", false); code != http.StatusCreated {
		t.Fatalf("static replacement: HTTP %d %s", code, body)
	}

	before, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Kind != store.AppKindStatic || before.Status != store.AppStatusRunning ||
		before.ActiveDeploymentID == "" || before.RuntimeID != "" || !before.EverContainer {
		t.Fatalf("static replacement state = %+v", before)
	}
	capture.mu.Lock()
	capture.removeCalled = false
	capture.mu.Unlock()

	e.srv.reconcileAppQuota(agent.ID)
	after, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Kind != store.AppKindStatic || after.Status != store.AppStatusRunning ||
		after.ActiveDeploymentID != before.ActiveDeploymentID || after.LastError != "" {
		t.Fatalf("watchdog damaged active static release: before=%+v after=%+v", before, after)
	}
	capture.mu.Lock()
	removeCalled := capture.removeCalled
	capture.mu.Unlock()
	if !removeCalled {
		t.Fatal("watchdog did not retry stale container cleanup for static app")
	}
}

func TestWatchdogFailClosesUnsafeReconciliation(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("unsafe-reconcile")
	agent := humanVerifyAgent(t, e, key, "unsafe-reconcile@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")

	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "health_path": "/healthz",
	}); failed {
		t.Fatalf("container deploy failed: %s", text)
	}
	capture.mu.Lock()
	capture.failReconcileUnsafe = true
	capture.stopCalled = false
	capture.mu.Unlock()

	e.srv.reconcileAppQuota(agent.ID)
	app, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != store.AppStatusError || !strings.Contains(app.LastError, "refusing to manage unsafe") {
		t.Fatalf("unsafe reconciliation did not fail closed: %+v", app)
	}
	capture.mu.Lock()
	stopped := capture.stopCalled
	capture.mu.Unlock()
	if !stopped {
		t.Fatal("unsafe reconciliation did not stop the app runtime")
	}
}

func TestSourceBuildImageIsRemovedWhenOldRuntimeDrainFails(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("source-cleanup")
	humanVerifyAgent(t, e, key, "source-cleanup@example.test")
	capture := attachMCPFakeRunner(t, e, "")

	body, _ := json.Marshal(map[string]any{
		"kind": "container", "image": "ghcr.io/example/app@sha256:" + strings.Repeat("a", 64),
		"health_path": "/",
	})
	resp, data := e.do(http.MethodPost, "/v1/apps/self/deploy", key, bytes.NewReader(body), "application/json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("initial image deploy: HTTP %d %s", resp.StatusCode, data)
	}
	uploadAppArchive(t, e, key, "source.tar.gz", makeAppTar(t,
		appTarEntry{Name: "Dockerfile", Body: []byte("FROM scratch\n")},
		appTarEntry{Name: "payload", Body: []byte("ok")},
	))
	capture.mu.Lock()
	capture.failStop = true
	capture.buildCalled = false
	capture.stopCalled = false
	capture.removeImageCalled = false
	capture.startCalled = false
	initialDeployCount := capture.deployCount
	capture.mu.Unlock()

	body, _ = json.Marshal(map[string]any{
		"kind": "container", "source": "source.tar.gz", "health_path": "/",
	})
	resp, data = e.do(http.MethodPost, "/v1/apps/self/deploy", key, bytes.NewReader(body), "application/json")
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(data), "drain previous runtime") {
		t.Fatalf("source replacement failure: HTTP %d %s", resp.StatusCode, data)
	}
	capture.mu.Lock()
	build := capture.build
	built := capture.buildCalled
	stopped := capture.stopCalled
	removed := capture.removeImageCalled
	removedImage := capture.removedImage
	restarted := capture.startCalled
	deployCount := capture.deployCount
	capture.mu.Unlock()
	if !built || !stopped || !removed || !restarted {
		t.Fatalf("cleanup lifecycle build=%v stop=%v remove_image=%v restart=%v", built, stopped, removed, restarted)
	}
	wantImage := "agenttransfer-app/" + build.AppID + ":" + build.ReleaseID
	if removedImage != wantImage {
		t.Fatalf("removed image = %q, want exact built tag %q", removedImage, wantImage)
	}
	if deployCount != initialDeployCount {
		t.Fatalf("replacement reached Deploy after ambiguous drain failure: calls %d -> %d", initialDeployCount, deployCount)
	}
}

func TestWatchdogFailClosesOverflowingStorageObservation(t *testing.T) {
	e := newAppTestEnv(t, maxStorageBytes)
	_, key := e.createAgent("overflowing-storage")
	agent := humanVerifyAgent(t, e, key, "overflowing-storage@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")
	if text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "health_path": "/healthz",
	}); failed {
		t.Fatalf("container deploy failed: %s", text)
	}
	app, err := e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.st.DB.Exec(`UPDATE app_deployments SET source_size=1 WHERE id=?`, app.ActiveDeploymentID); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	capture.dataBytes = maxStorageBytes // models a huge sparse /data observation
	capture.stopCalled = false
	capture.mu.Unlock()

	e.srv.reconcileAppQuota(agent.ID)
	app, err = e.srv.st.AppByAgentID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != store.AppStatusError || !strings.Contains(app.LastError, "invalid") {
		t.Fatalf("overflowing storage observation did not fail closed: %+v", app)
	}
	capture.mu.Lock()
	stopped := capture.stopCalled
	capture.mu.Unlock()
	if !stopped {
		t.Fatal("overflowing storage observation did not stop the runtime")
	}
}

func TestHostedMCPDeployImageRejectsSourceAndBoundsLogs(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	_, key := e.createAgent("mcp-validation")
	humanVerifyAgent(t, e, key, "validation-owner@example.test")

	text, failed := hostedMCPTool(t, e, key, "deploy_app_image", map[string]any{
		"image": "example/app:1", "path": "/private/site",
	})
	if !failed || !strings.Contains(text, "local stdio bridge") {
		t.Fatalf("source explanation failed=%v: %s", failed, text)
	}
	text, failed = hostedMCPTool(t, e, key, "app_logs", map[string]any{"tail": 2001})
	if !failed || !strings.Contains(text, "between 1 and 2000") {
		t.Fatalf("log bound failed=%v: %s", failed, text)
	}
}
