package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// The SSRF guard must reject every non-public address class and accept public
// unicast. This is the load-bearing webhook control.
func TestWebhookSSRFGuard(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.169.254",         // cloud metadata (link-local)
		"fe80::1",                 // link-local v6
		"fc00::1", "fd12:3456::1", // ULA
		"100.64.0.1",               // CGNAT
		"198.18.0.1",               // benchmarking
		"0.0.0.0", "0.1.2.3", "::", // unspecified/current network
		"224.0.0.1", "ff02::1", // multicast
		"255.255.255.255",  // limited broadcast
		"::ffff:127.0.0.1", // IPv4-mapped loopback (must unmap + block)
		"::ffff:10.0.0.1",  // IPv4-mapped private
		"192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1",
		"192.88.99.1", "192.175.48.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
		"64:ff9b::1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "5f00::1", "fec0::1",
	}
	for _, s := range blocked {
		if publicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("SSRF: %s wrongly allowed", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, s := range allowed {
		if !publicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("SSRF: public %s wrongly blocked", s)
		}
	}
}

// Registration rejects internal/metadata/credential/non-http URLs.
func TestWebhookURLValidation(t *testing.T) {
	e := newEnv(t) // allowPrivateWebhooks defaults false
	_, key := e.createAgent("alice")
	for _, u := range []string{
		"http://localhost/hook", "http://169.254.169.254/latest/meta-data",
		"ftp://example.com/x", "https://user:pass@example.com/x",
		"http://127.0.0.1:9000/x",
	} {
		code := e.doJSON("POST", "/v1/webhooks", key, map[string]any{"url": u}, nil)
		if code != 400 {
			t.Errorf("webhook url %q: got %d, want 400", u, code)
		}
	}
}

// End-to-end: a message arrival delivers a signed, reference-only webhook.
func TestWebhookDeliveryAndSignature(t *testing.T) {
	e := newEnv(t)
	e.srv.allowPrivateWebhooks = true // permit the loopback sink

	type hit struct {
		id, ts, sig string
		body        []byte
	}
	hits := make(chan hit, 4)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits <- hit{r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"), b}
		w.WriteHeader(200)
	}))
	defer sink.Close()

	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")

	// Alice registers a webhook; capture the one-time secret.
	var reg struct {
		Secret string `json:"secret"`
	}
	if code := e.doJSON("POST", "/v1/webhooks", aliceKey, map[string]any{"url": sink.URL}, &reg); code != 201 {
		t.Fatalf("register webhook: %d", code)
	}
	if reg.Secret == "" {
		t.Fatal("no secret returned")
	}

	// Bob sends Alice a message → enqueues a delivery to her webhook.
	if code := e.doJSON("POST", "/v1/send", bobKey, map[string]any{"to": []string{"alice@local"}, "note": "ping"}, nil); code != 201 {
		t.Fatalf("send: %d", code)
	}

	// Drain the queue synchronously (no ticker wait).
	e.srv.deliverWebhookBatch(e.srv.newWebhookClient())

	select {
	case h := <-hits:
		// Signature must verify over id.timestamp.body with the shared secret.
		tsInt, _ := strconv.ParseInt(h.ts, 10, 64)
		want, err := signWebhook(reg.Secret, h.id, tsInt, h.body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := webhookSecretKey(reg.Secret)
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(h.id + "." + h.ts + "."))
		mac.Write(h.body)
		recomputed := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if h.sig != want || h.sig != recomputed {
			t.Fatalf("signature mismatch: header=%s want=%s", h.sig, want)
		}
		// Payload is reference-only: has resource_url, no secret/bytes.
		var p map[string]any
		if err := json.Unmarshal(h.body, &p); err != nil {
			t.Fatalf("payload not JSON: %s", h.body)
		}
		if p["resource_url"] == nil || p["type"] != "message.received" {
			t.Fatalf("payload wrong: %v", p)
		}
		if _, leaked := p["secret"]; leaked {
			t.Fatal("payload leaked a secret")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook never delivered")
	}

	// List must not re-expose the secret.
	var list struct {
		Webhooks []map[string]any `json:"webhooks"`
	}
	e.doJSON("GET", "/v1/webhooks", aliceKey, nil, &list)
	if len(list.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(list.Webhooks))
	}
	if s, _ := list.Webhooks[0]["secret"].(string); s != "" {
		t.Fatal("list exposed the raw secret")
	}
}

func TestWebhookStandardSignatureVector(t *testing.T) {
	// The serialized secret decodes to the raw HMAC key "abcdefghijklmnopqrstuvwx".
	// This independently exercises the Standard Webhooks whsec_ decoding rule.
	secret := "whsec_" + base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwx"))
	got, err := signWebhook(secret, "msg_1", 1, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("abcdefghijklmnopqrstuvwx"))
	mac.Write([]byte("msg_1.1.{}"))
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
	if _, err := signWebhook("not-a-secret", "msg_1", 1, nil); err == nil {
		t.Fatal("malformed secret accepted")
	}
}

// A delivery that keeps failing eventually goes dead (bounded retries).
func TestWebhookDeadLetter(t *testing.T) {
	e := newEnv(t)
	e.srv.allowPrivateWebhooks = true
	// A sink that always 500s.
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer sink.Close()
	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")
	e.doJSON("POST", "/v1/webhooks", aliceKey, map[string]any{"url": sink.URL}, nil)
	e.doJSON("POST", "/v1/send", bobKey, map[string]any{"to": []string{"alice@local"}, "note": "x"}, nil)

	// Force the single delivery through all attempts by resetting next_attempt_at
	// to now between drains (bypassing the backoff wait) until it's dead.
	db := e.srv.Store().DB
	for i := 0; i < webhookMaxAttempts+2; i++ {
		db.Exec(`UPDATE webhook_deliveries SET next_attempt_at=0 WHERE status='pending'`)
		e.srv.deliverWebhookBatch(e.srv.newWebhookClient())
	}
	var dead int
	db.QueryRow(`SELECT COUNT(*) FROM webhook_deliveries WHERE status='dead'`).Scan(&dead)
	if dead != 1 {
		t.Fatalf("expected 1 dead delivery after exhausting retries, got %d", dead)
	}
}
