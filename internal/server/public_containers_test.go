package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOpenSignupContainersRequireExplicitOperatorOptIn(t *testing.T) {
	e := newEnvCfg(t, Config{
		OpenSignup:      true,
		AppDomain:       testAppDomain,
		AppStorageQuota: 1 << 20,
		AppBundleSize:   1 << 20,
		BehindProxy:     true,
	})
	_, key := e.createAgent("public-workload")
	humanVerifyAgent(t, e, key, "public-owner@example.com")
	code, body := e.do(http.MethodPost, "/v1/apps/self/deploy", key,
		strings.NewReader(`{"kind":"container","image":"alpine:latest"}`), "application/json")
	if code.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "ALLOW_PUBLIC_CONTAINERS") {
		t.Fatalf("container deploy = HTTP %d %s", code.StatusCode, body)
	}

	e.srv.appReadyMu.Lock()
	e.srv.appReady = appHostingReadiness{
		RunnerConfigured: true, RunnerReady: true, WildcardDNSReady: true, CheckedAt: time.Now(),
	}
	e.srv.appReadyMu.Unlock()
	var discovery map[string]any
	if status := e.doJSON(http.MethodGet, "/.well-known/agenttransfer", "", nil, &discovery); status != http.StatusOK {
		t.Fatalf("well-known HTTP %d", status)
	}
	hosting := discovery["app_hosting"].(map[string]any)
	if containers, _ := hosting["containers"].(bool); containers {
		t.Fatal("discovery advertised public containers without operator opt-in")
	}
}
