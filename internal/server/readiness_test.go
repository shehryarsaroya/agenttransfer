package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryAdvertisesContainersOnlyWhenAppInfrastructureIsReady(t *testing.T) {
	e := newEnvCfg(t, Config{AppDomain: testAppDomain, BehindProxy: true, AllowUnenforcedAppData: true})
	setReady := func(runner, wildcard bool) {
		e.srv.appReadyMu.Lock()
		e.srv.appReady = appHostingReadiness{
			RunnerConfigured: true,
			RunnerReady:      runner,
			WildcardDNSReady: wildcard,
			CheckedAt:        time.Now(),
		}
		e.srv.appReadyMu.Unlock()
	}
	containers := func() bool {
		var out map[string]any
		if code := e.doJSON(http.MethodGet, "/.well-known/agenttransfer", "", nil, &out); code != http.StatusOK {
			t.Fatalf("well-known HTTP %d", code)
		}
		hosting, ok := out["app_hosting"].(map[string]any)
		if !ok {
			t.Fatalf("app_hosting = %#v", out["app_hosting"])
		}
		value, _ := hosting["containers"].(bool)
		return value
	}

	setReady(true, true)
	if !containers() {
		t.Fatal("ready container hosting was not advertised")
	}
	setReady(false, true)
	if containers() {
		t.Fatal("unhealthy runner was advertised")
	}
	setReady(true, false)
	if containers() {
		t.Fatal("container hosting without wildcard DNS was advertised")
	}
}

func TestDeployFailsFastWhenAppInfrastructureIsUnready(t *testing.T) {
	e := newEnvCfg(t, Config{
		AppDomain: testAppDomain, BehindProxy: true, AllowUnenforcedAppData: true,
	})
	_, key := e.createAgent("readiness-deploy")
	humanVerifyAgent(t, e, key, "ready-owner@example.test")
	setStatus := func(status appHostingReadiness) {
		status.CheckedAt = time.Now()
		e.srv.appReadyMu.Lock()
		e.srv.appReady = status
		e.srv.appReadyMu.Unlock()
	}
	deploy := func(body map[string]any) (int, string) {
		payload, _ := json.Marshal(body)
		resp, data := e.do(http.MethodPost, "/v1/apps/self/deploy", key, bytes.NewReader(payload), "application/json")
		return resp.StatusCode, string(data)
	}

	setStatus(appHostingReadiness{})
	if code, body := deploy(map[string]any{"kind": "static", "source": "missing.tar.gz"}); code != http.StatusServiceUnavailable || !strings.Contains(body, "wildcard DNS") {
		t.Fatalf("unready wildcard deploy = HTTP %d %s", code, body)
	}
	setStatus(appHostingReadiness{WildcardDNSReady: true})
	if code, body := deploy(map[string]any{"kind": "container", "image": "example/app:1"}); code != http.StatusServiceUnavailable || !strings.Contains(body, "runner") {
		t.Fatalf("unready runner deploy = HTTP %d %s", code, body)
	}
}

func TestUnprovenInternalNetworkPermitsFirstContainerDeploy(t *testing.T) {
	e := newEnvCfg(t, Config{
		AppDomain: testAppDomain, BehindProxy: true, AllowUnenforcedAppData: true,
	})
	_, key := e.createAgent("readiness-probe")
	humanVerifyAgent(t, e, key, "probe-owner@example.test")
	capture := attachMCPFakeRunner(t, e, "logs")
	capture.mu.Lock()
	capture.containerReady = false
	capture.containerState = "unknown"
	capture.mu.Unlock()
	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{
		RunnerConfigured: true, RunnerReady: false, WildcardDNSReady: true, CheckedAt: time.Now(),
	}
	e.srv.appReadyMu.Unlock()

	payload, _ := json.Marshal(map[string]any{"kind": "container", "image": "example/app:1"})
	resp, body := e.do(http.MethodPost, "/v1/apps/self/deploy", key, bytes.NewReader(payload), "application/json")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first capability-probe deploy = HTTP %d %s", resp.StatusCode, body)
	}
	if _, containers := e.srv.advertisedAppHosting(t.Context()); !containers {
		t.Fatal("successful capability-probe deploy did not refresh container readiness")
	}
}

func TestHumanAndLLMSurfacesHideUnreadyAppHosting(t *testing.T) {
	e := newEnvCfg(t, Config{AppDomain: testAppDomain, BehindProxy: true})
	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{CheckedAt: time.Now()}
	e.srv.appReadyMu.Unlock()

	resp, body := e.do(http.MethodGet, "/", "", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index HTTP %d", resp.StatusCode)
	}
	if bytes.Contains(body, []byte(`id="apps"`)) || bytes.Contains(body, []byte(testAppDomain)) {
		t.Fatalf("unready app hosting was advertised on index: %.300s", body)
	}
	resp, _ = e.do(http.MethodGet, "/launch", "", nil, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unready launch page HTTP %d", resp.StatusCode)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/llms.txt", nil)
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "host an app") || strings.Contains(rec.Body.String(), testAppDomain) {
		t.Fatalf("unready app hosting was advertised in llms.txt: %.300s", rec.Body.String())
	}

	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{WildcardDNSReady: true, CheckedAt: time.Now()}
	e.srv.appReadyMu.Unlock()
	resp, body = e.do(http.MethodGet, "/", "", nil, "")
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`id="apps"`)) || !bytes.Contains(body, []byte(testAppDomain)) {
		t.Fatalf("ready app hosting missing from index: HTTP %d", resp.StatusCode)
	}
}

func TestCoreHealthSurfacesOptionalAppFailureWithoutFailing(t *testing.T) {
	e := newAppTestEnv(t, 0)
	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{RunnerConfigured: true, CheckedAt: time.Now()}
	e.srv.appReadyMu.Unlock()
	resp, body := e.do(http.MethodGet, "/healthz", "", nil, "")
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("healthz = HTTP %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-AgentTransfer-App-Runner"); got != "disabled" {
		t.Fatalf("runner readiness header = %q", got)
	}
	if got := resp.Header.Get("X-AgentTransfer-App-Wildcard-DNS"); got != "unavailable" {
		t.Fatalf("wildcard readiness header = %q", got)
	}
}
