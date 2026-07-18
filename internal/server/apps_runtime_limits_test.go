package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

func TestAppProxyRejectsOversizedBodiesAndExcessConcurrency(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	app := store.App{ID: "app-demo", Slug: "demo", RuntimeID: "runtime", Upstream: upstream.URL}
	e.srv.rememberRuntimeTarget(app.ID, app.RuntimeID, app.Upstream)

	e.srv.cfg.AppProxyBodySize = 4
	req := httptest.NewRequest(http.MethodPost, "http://demo.apps.test/upload", strings.NewReader("12345"))
	rec := httptest.NewRecorder()
	e.srv.proxyContainerApp(rec, req, app)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body HTTP %d", rec.Code)
	}

	e.srv.appProxySlots = make(chan struct{}, 1)
	e.srv.appProxySlots <- struct{}{}
	req = httptest.NewRequest(http.MethodGet, "http://demo.apps.test/", nil)
	rec = httptest.NewRecorder()
	e.srv.proxyContainerApp(rec, req, app)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("proxy capacity response HTTP %d headers=%v", rec.Code, rec.Header())
	}
	<-e.srv.appProxySlots

	e.srv.cfg.AppProxyPerAppConcurrency = 1
	e.srv.appProxyAppSlots = sync.Map{}
	appSlots := e.srv.appProxySlot(app.ID)
	appSlots <- struct{}{}
	req = httptest.NewRequest(http.MethodGet, "http://demo.apps.test/", nil)
	rec = httptest.NewRecorder()
	e.srv.proxyContainerApp(rec, req, app)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("per-app capacity HTTP %d", rec.Code)
	}
	other := app
	other.ID, other.Slug = "app-other", "other"
	e.srv.rememberRuntimeTarget(other.ID, other.RuntimeID, other.Upstream)
	req = httptest.NewRequest(http.MethodGet, "http://other.apps.test/", nil)
	rec = httptest.NewRecorder()
	e.srv.proxyContainerApp(rec, req, other)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("one saturated app blocked another: HTTP %d", rec.Code)
	}
}

func TestRuntimeHealthProbeRetriesAndRejectsPublicTargets(t *testing.T) {
	var attempts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		if attempts.Add(1) < 3 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ctx := t.Context()
	if err := probeRuntimeHealth(ctx, upstream.URL, "/ready"); err != nil {
		t.Fatalf("health probe did not recover: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("health attempts = %d", attempts.Load())
	}
	if err := probeRuntimeHealth(ctx, "http://192.0.2.1:8080", "/ready"); err == nil {
		t.Fatal("health probe accepted a public upstream")
	}
}

func TestPrivateRuntimeTargetRequiresExactRunnerAttestation(t *testing.T) {
	e := newAppTestEnv(t, 1<<20)
	app := store.App{
		ID: "app-demo", RuntimeID: "aaaaaaaaaaaa",
		Upstream: "http://10.23.0.7:8080",
	}
	e.srv.rememberRuntimeTarget(app.ID, app.RuntimeID, app.Upstream)
	target, err := e.srv.trustedRuntimeTarget(t.Context(), app)
	if err != nil || target.String() != app.Upstream {
		t.Fatalf("attested private target = %v, %v", target, err)
	}

	tampered := app
	tampered.Upstream = "http://10.23.0.8:8080"
	if _, err := e.srv.trustedRuntimeTarget(t.Context(), tampered); err == nil {
		t.Fatal("private target differing from runner attestation was accepted")
	}
	tampered = app
	tampered.RuntimeID = "bbbbbbbbbbbb"
	if _, err := e.srv.trustedRuntimeTarget(t.Context(), tampered); err == nil {
		t.Fatal("private target with a different runtime id was accepted")
	}
	for _, raw := range []string{"http://8.8.8.8:8080", "http://169.254.1.2:8080"} {
		tampered = app
		tampered.Upstream = raw
		if _, err := e.srv.trustedRuntimeTarget(t.Context(), tampered); err == nil {
			t.Fatalf("unsafe target %q was accepted", raw)
		}
	}
}

func TestAppProxyResponseHeaderTimeoutIsConfigured(t *testing.T) {
	e := newEnvCfg(t, Config{
		AppDomain:                     testAppDomain,
		BehindProxy:                   true,
		AppProxyResponseHeaderTimeout: 75 * time.Millisecond,
	})
	if got := e.srv.appProxyTransport.ResponseHeaderTimeout; got != 75*time.Millisecond {
		t.Fatalf("response header timeout = %s", got)
	}
}
