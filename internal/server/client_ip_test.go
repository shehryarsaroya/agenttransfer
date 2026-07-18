package server

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPValidatesTrustedProxyHop(t *testing.T) {
	s := &Server{cfg: Config{BehindProxy: true}}
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{name: "proxy appended IPv4", xff: "198.51.100.8, 203.0.113.9", want: "203.0.113.9"},
		{name: "proxy appended IPv6", xff: "198.51.100.8, 2001:db8::1", want: "2001:db8::1"},
		{name: "invalid falls back to peer", xff: "spoofed", want: "192.0.2.20"},
		{name: "empty falls back to peer", want: "192.0.2.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.test/", nil)
			r.RemoteAddr = "192.0.2.20:4321"
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := s.clientIP(r); got != tt.want {
				t.Fatalf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}
