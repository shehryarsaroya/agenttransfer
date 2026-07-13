package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
)

type mcpRunnerCapture struct {
	mu           sync.Mutex
	deploy       apphost.DeployRequest
	logTail      string
	stopCalled   bool
	removeCalled bool
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
	capture := &mcpRunnerCapture{}
	runtimeID := "aaaaaaaaaaaa"
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
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
		capture.mu.Unlock()
		write(w, apphost.DeployResponse{
			AppID: req.AppID, ReleaseID: req.ReleaseID, RuntimeID: runtimeID,
			ContainerName: "agenttransfer-test", Upstream: "http://127.0.0.1:32123",
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
		capture.mu.Unlock()
		write(w, apphost.AppStatus{
			AppID: deploy.AppID, ReleaseID: deploy.ReleaseID, Image: deploy.Image,
			ContainerID: runtimeID, State: "running", Running: true,
		})
	})
	mux.HandleFunc("POST /v1/runtimes/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.stopCalled = true
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.StopResult{AppID: deploy.AppID, RuntimeID: runtimeID, Stopped: true})
	})
	mux.HandleFunc("POST /v1/apps/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.stopCalled = true
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.StopResult{AppID: deploy.AppID, Stopped: true, StoppedIDs: []string{runtimeID}})
	})
	mux.HandleFunc("POST /v1/apps/{id}/remove", func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		capture.removeCalled = true
		deploy := capture.deploy
		capture.mu.Unlock()
		write(w, apphost.RemoveAppResult{AppID: deploy.AppID, RemovedRuntimes: 1})
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

	if code := e.doJSON(http.MethodDelete, "/v1/apps/self", key, nil, nil); code != http.StatusOK {
		t.Fatalf("delete app: HTTP %d", code)
	}
	capture.mu.Lock()
	removeCalled := capture.removeCalled
	capture.mu.Unlock()
	if !removeCalled {
		t.Fatal("app deletion orphaned its stopped runtime")
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
