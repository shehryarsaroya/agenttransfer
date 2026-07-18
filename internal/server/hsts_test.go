package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHSTSUsesForwardedProtoOnlyBehindConfiguredProxy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		behindProxy bool
		wantHSTS    bool
	}{
		{name: "untrusted spoof ignored", behindProxy: false, wantHSTS: false},
		{name: "trusted proxy honored", behindProxy: true, wantHSTS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnvCfg(t, Config{BehindProxy: tc.behindProxy})
			req := httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			rec := httptest.NewRecorder()
			e.srv.Handler().ServeHTTP(rec, req)
			got := rec.Header().Get("Strict-Transport-Security") != ""
			if got != tc.wantHSTS {
				t.Fatalf("HSTS present = %v, want %v", got, tc.wantHSTS)
			}
		})
	}
}
