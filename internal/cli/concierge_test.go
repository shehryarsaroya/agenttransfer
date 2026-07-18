package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func trustedConciergeMessage() conciergeMessage {
	var m conciergeMessage
	m.ID = "msg_1"
	m.From = "alice@agents.test"
	m.DKIM = "local"
	m.Sender.DomainVerified = true
	m.Offer.URL = "https://agents.test/f/token"
	m.Offer.Trusted = true
	return m
}

func TestConciergeRequiresAuthenticatedLocalProvenance(t *testing.T) {
	base := trustedConciergeMessage()
	if !conciergeAllows(base, "concierge@agents.test", "agents.test") {
		t.Fatal("authenticated local message was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*conciergeMessage)
	}{
		{"spoofed-from", func(m *conciergeMessage) { m.DKIM = "fail" }},
		{"remote-dkim", func(m *conciergeMessage) { m.DKIM = "pass" }},
		{"missing-sender-proof", func(m *conciergeMessage) { m.Sender.DomainVerified = false }},
		{"untrusted-offer", func(m *conciergeMessage) { m.Offer.Trusted = false }},
		{"remote-domain", func(m *conciergeMessage) { m.From = "alice@elsewhere.test" }},
		{"quarantined", func(m *conciergeMessage) { m.Quarantined = true }},
		{"self", func(m *conciergeMessage) { m.From = "concierge@agents.test" }},
		{"missing-id", func(m *conciergeMessage) { m.ID = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base
			tt.mutate(&m)
			if conciergeAllows(m, "concierge@agents.test", "agents.test") {
				t.Fatal("untrusted message was accepted")
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConciergeRejectsMalformedHashBeforeFetch(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, nil
	})}
	for _, hash := range []string{"", "abc", strings.Repeat("z", 64)} {
		reply := conciergeReply(client, "https://example.test", "payload.bin", "https://example.test/f/x", hash, 1, "", "", 100)
		if !strings.Contains(reply, "invalid sha256") {
			t.Fatalf("hash %q reply = %q", hash, reply)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed hashes triggered %d network request(s)", calls.Load())
	}
}

func TestConciergeActualByteCapIgnoresClaimedSize(t *testing.T) {
	body := []byte("12345")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // force unknown/chunked length; exercise streaming cap
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	reply := conciergeReply(newConciergeHTTPClient(srv.URL), srv.URL, "payload.bin", srv.URL, hex.EncodeToString(sum[:]), 0, "", "", 4)
	if !strings.Contains(reply, "exceeded the 4-byte limit") {
		t.Fatalf("reply = %q", reply)
	}
}

func TestConciergeRejectsOverflowingByteLimit(t *testing.T) {
	if _, _, err := fetchAndHash(http.DefaultClient, "https://agents.test", "https://agents.test/f/x", math.MaxInt64); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("overflowing byte limit error = %v", err)
	}
}

func TestConciergeBlocksLoopbackAtDialBoundary(t *testing.T) {
	err := conciergeDialControl(false)("tcp4", "127.0.0.1:80", nil)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback error = %v", err)
	}
}

func TestConciergeBlocksSpecialPurposeAddresses(t *testing.T) {
	for _, address := range []string{
		"0.0.0.1", "100.64.0.1", "192.0.0.1", "192.0.2.1", "192.31.196.1",
		"192.52.193.1", "192.88.99.1", "192.175.48.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "240.0.0.1",
		"64:ff9b::1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "5f00::1", "fec0::1",
	} {
		if conciergePublicUnicast(netip.MustParseAddr(address)) {
			t.Errorf("special-purpose address %s was allowed", address)
		}
	}
}

func TestConciergeRequiresExactInstanceOrigin(t *testing.T) {
	_, _, err := fetchAndHash(newConciergeHTTPClient("https://agents.test"), "https://agents.test", "https://other.test/file", 100)
	if err == nil || !strings.Contains(err.Error(), "configured instance origin") {
		t.Fatalf("cross-origin error = %v", err)
	}
}

func TestConciergeNeverFollowsRedirects(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/internal", http.StatusFound)
			return
		}
		reached.Store(true)
		_, _ = io.WriteString(w, "secret")
	}))
	defer srv.Close()

	_, _, err := fetchAndHash(newConciergeHTTPClient(srv.URL), srv.URL, srv.URL+"/redirect", 100)
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect error = %v", err)
	}
	if reached.Load() {
		t.Fatal("redirect target was fetched")
	}
}

func TestConciergeMarksReadOnlyAfterIdempotentReplySucceeds(t *testing.T) {
	var sends, reads atomic.Int32
	var failSend atomic.Bool
	failSend.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/send":
			sends.Add(1)
			if got := r.Header.Get("Idempotency-Key"); got != "concierge-msg_1" {
				t.Errorf("idempotency key = %q", got)
			}
			if failSend.Load() {
				http.Error(w, `{"error":"temporary failure"}`, http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{}`)
		case "/v1/inbox/msg_1/read":
			reads.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"read":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := newAPI(clientConfig{URL: srv.URL, APIKey: "test-key"})
	m := trustedConciergeMessage()
	if err := replyAndMarkRead(a, m, "hello"); err == nil {
		t.Fatal("failed reply was reported as successful")
	}
	if got := reads.Load(); got != 0 {
		t.Fatalf("failed reply marked message read %d time(s)", got)
	}

	failSend.Store(false)
	if err := replyAndMarkRead(a, m, "hello"); err != nil {
		t.Fatal(err)
	}
	if got := sends.Load(); got != 2 {
		t.Fatalf("send attempts = %d, want 2", got)
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("successful reply marked message read %d time(s), want 1", got)
	}
}

func TestConciergeFetchHasOverallTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}))
	defer srv.Close()

	client := newConciergeHTTPClient(srv.URL)
	client.Timeout = 20 * time.Millisecond
	_, _, err := fetchAndHash(client, srv.URL, srv.URL, 100)
	if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestSenderLimiterPrunesInactiveSenders(t *testing.T) {
	l := newSenderLimiter(2)
	l.hits["gone@agents.test"] = []senderHit{{messageID: "msg_old", at: time.Now().Add(-2 * time.Hour)}}
	l.lastPrune = time.Now().Add(-2 * time.Minute)
	if !l.allow("active@agents.test", "msg_new") {
		t.Fatal("active sender was unexpectedly limited")
	}
	if _, ok := l.hits["gone@agents.test"]; ok {
		t.Fatal("expired sender entry was not pruned")
	}
}

func TestSenderLimiterDoesNotChargeMessageRetryTwice(t *testing.T) {
	l := newSenderLimiter(1)
	if !l.allow("alice@agents.test", "msg_1") {
		t.Fatal("first message attempt was unexpectedly limited")
	}
	if !l.allow("alice@agents.test", "msg_1") {
		t.Fatal("same-message retry was unexpectedly limited")
	}
	if l.allow("alice@agents.test", "msg_2") {
		t.Fatal("distinct second reply exceeded the sender budget")
	}
}
