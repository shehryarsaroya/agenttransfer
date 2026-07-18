package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// Webhooks push a small, signed, reference-only notification to an agent's
// registered URL when a message arrives — a push alternative to long-polling.
// The payload never carries file bytes, tokens, or keys: the agent fetches the
// referenced resource with its own API key, so a webhook can't leak what a
// transfer's encryption is protecting.

const (
	webhookMaxAttempts   = 8                // then the delivery is dead
	webhookBackoffBase   = 10 * time.Second // exponential base
	webhookBackoffCap    = 6 * time.Hour
	webhookAutoDisableAt = 15               // consecutive dead deliveries → disable the endpoint
	webhookAttemptBudget = 15 * time.Second // total per POST
)

// webhookPayload is the reference-only notification body.
type webhookPayload struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	From        string `json:"from,omitempty"`
	ResourceURL string `json:"resource_url"`
}

// enqueueWebhooks fans a message arrival out to the agent's enabled endpoints.
// Cheap no-op when the agent has none. Reference-only: the body points at the
// inbox message, which the agent then GETs with its own key.
func (s *Server) enqueueWebhooks(agentID, eventType, msgID, from string) {
	if !s.st.HasEnabledWebhooks(agentID) {
		return
	}
	body, _ := json.Marshal(webhookPayload{
		Type:        eventType,
		ID:          msgID,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		From:        from,
		ResourceURL: s.BaseURL() + "/v1/inbox/" + msgID,
	})
	if err := s.st.EnqueueDeliveries(agentID, eventType, body); err != nil {
		log.Printf("webhook: enqueue for %s: %v", agentID, err)
	}
}

// ---- SSRF-safe delivery client ----

// webhookDialControl runs after DNS resolution, right before connect(2): its
// address is the concrete ip:port the socket will use, so validating here is
// atomic with the connection and immune to DNS-rebinding (a hostname that
// resolves public at check time and internal at dial time). Redirects reuse
// the transport, so this re-fires per hop.
func (s *Server) webhookDialControl(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("blocked network %q", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if s.allowPrivateWebhooks { // tests only
		return nil
	}
	if !publicUnicast(ip) {
		return fmt.Errorf("blocked non-public address %s (SSRF guard)", ip)
	}
	return nil
}

// specialPurposeDenyPrefixes covers the IANA special-purpose registries that
// Go's address helpers still regard as global unicast. Webhooks have no reason
// to target protocol anycasts, documentation, benchmarking, translation, or
// reserved space, so the SSRF boundary deliberately denies the full ranges.
var specialPurposeDenyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),         // current network
	netip.MustParsePrefix("100.64.0.0/10"),     // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),      // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),      // documentation TEST-NET-1
	netip.MustParsePrefix("192.31.196.0/24"),   // AS112-v4
	netip.MustParsePrefix("192.52.193.0/24"),   // AMT
	netip.MustParsePrefix("192.88.99.0/24"),    // deprecated 6to4 relay anycast
	netip.MustParsePrefix("192.175.48.0/24"),   // direct-delegation AS112
	netip.MustParsePrefix("198.18.0.0/15"),     // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),   // documentation TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),    // documentation TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),       // reserved and limited broadcast
	netip.MustParsePrefix("::/96"),             // IPv4-compatible IPv6 (deprecated)
	netip.MustParsePrefix("64:ff9b::/96"),      // well-known NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),    // local-use NAT64
	netip.MustParsePrefix("100::/64"),          // discard-only
	netip.MustParsePrefix("100:0:0:1::/64"),    // dummy IPv6 prefix
	netip.MustParsePrefix("2001::/23"),         // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),     // documentation
	netip.MustParsePrefix("2002::/16"),         // 6to4
	netip.MustParsePrefix("2620:4f:8000::/48"), // direct-delegation AS112
	netip.MustParsePrefix("3fff::/20"),         // documentation
	netip.MustParsePrefix("5f00::/16"),         // segment-routing SIDs
	netip.MustParsePrefix("fec0::/10"),         // deprecated IPv6 site-local
}

// publicUnicast reports whether ip is a globally routable unicast address safe
// to send a webhook to.
func publicUnicast(ip netip.Addr) bool {
	ip = ip.Unmap()                                                                   // ::ffff:10.0.0.1 → 10.0.0.1
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || // IsPrivate = RFC1918 + fc00::/7
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || // 169.254/16 (incl. cloud metadata), fe80::/10
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range specialPurposeDenyPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *Server) newWebhookClient() *http.Client {
	return &http.Client{
		Timeout: webhookAttemptBudget,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects (a webhook has no reason to 3xx)
		},
		Transport: &http.Transport{
			Proxy: nil, // ignore environment proxies
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
				Control: s.webhookDialControl,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

// validateWebhookURL checks the scheme and that the host resolves only to
// public addresses (fail-fast at registration; the dial-time control is the
// rebinding-proof backstop).
func (s *Server) validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad url")
	}
	if u.User != nil {
		return fmt.Errorf("url must not contain credentials")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("url has no host")
	}
	if s.allowPrivateWebhooks { // tests: allow http loopback sink
		return nil
	}
	// Production: require https — the payload is signed but a plaintext http
	// endpoint still exposes message ids + sender to a passive observer.
	if u.Scheme != "https" {
		return fmt.Errorf("url must be https")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("url host does not resolve")
	}
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok || !publicUnicast(a) {
			return fmt.Errorf("url resolves to a non-public address")
		}
	}
	return nil
}

// webhookSecretKey decodes the serialized Standard Webhooks signing secret.
// The whsec_ prefix is an identifier; only the decoded random bytes are the
// HMAC key. Accept both standard and URL-safe base64 so secrets generated by
// older AgentTransfer releases continue to work after this interoperability
// fix.
func webhookSecretKey(secret string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(secret, "whsec_")
	if !ok || encoded == "" {
		return nil, errors.New("invalid webhook secret")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		key, err := encoding.DecodeString(encoded)
		if err == nil && len(key) >= 24 && len(key) <= 64 {
			return key, nil
		}
	}
	return nil, errors.New("invalid webhook secret")
}

// signWebhook returns the Standard Webhooks signature "v1,<base64 hmac-sha256
// of id.timestamp.body>".
func signWebhook(secret, id string, ts int64, body []byte) (string, error) {
	key, err := webhookSecretKey(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func newWebhookSecret() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

// ---- delivery worker ----

// webhookWorker drains due deliveries on a short ticker (the 60s janitor is too
// coarse for early retries). One pass per tick; each POST is signed fresh so a
// late retry still passes the receiver's timestamp tolerance.
func (s *Server) webhookWorker(ctx context.Context) {
	_ = s.st.ResetStaleDeliveries() // reclaim anything stuck 'delivering' from a crash
	client := s.newWebhookClient()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.deliverWebhookBatch(client)
		}
	}
}

// webhookConcurrency bounds simultaneous in-flight POSTs so one hanging
// endpoint (up to webhookAttemptBudget) can't stall the whole queue — without
// it, a single sequential worker × 15s × 50 could freeze all delivery for
// minutes.
const webhookConcurrency = 8

func (s *Server) deliverWebhookBatch(client *http.Client) {
	batch, err := s.st.ClaimDueDeliveries(50)
	if err != nil {
		log.Printf("webhook: claim: %v", err)
		return
	}
	sem := make(chan struct{}, webhookConcurrency)
	var wg sync.WaitGroup
	for _, d := range batch {
		sem <- struct{}{}
		wg.Add(1)
		go func(d store.WebhookDelivery) {
			defer wg.Done()
			defer func() { <-sem }()
			s.deliverOne(client, d)
		}(d)
	}
	wg.Wait()
}

func (s *Server) deliverOne(client *http.Client, d store.WebhookDelivery) {
	ts := time.Now().Unix()
	req, err := http.NewRequest("POST", d.URL, bytes.NewReader(d.Payload))
	if err != nil {
		s.webhookFailed(d, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AgentTransfer-Webhooks/1")
	req.Header.Set("Webhook-Id", d.ID)
	req.Header.Set("Webhook-Timestamp", strconv.FormatInt(ts, 10))
	sig, err := signWebhook(d.Secret, d.ID, ts, d.Payload)
	if err != nil {
		s.webhookFailed(d, 0, err.Error())
		return
	}
	req.Header.Set("Webhook-Signature", sig)

	resp, err := client.Do(req)
	if err != nil {
		s.webhookFailed(d, 0, err.Error())
		return
	}
	code := resp.StatusCode
	resp.Body.Close()
	if code >= 200 && code < 300 {
		_ = s.st.MarkDelivered(d.ID, d.WebhookID, code)
		return
	}
	s.webhookFailed(d, code, fmt.Sprintf("HTTP %d", code))
}

// webhookFailed either reschedules with backoff+jitter or, past the attempt
// budget, marks the delivery dead and auto-disables the endpoint after enough
// consecutive dead deliveries (notifying the owner out-of-band).
func (s *Server) webhookFailed(d store.WebhookDelivery, code int, errStr string) {
	if d.Attempts+1 >= webhookMaxAttempts {
		failCount, err := s.st.FailDeliveryDead(d.ID, d.WebhookID, code, errStr)
		if err != nil {
			log.Printf("webhook: mark dead: %v", err)
			return
		}
		if failCount >= webhookAutoDisableAt {
			_ = s.st.DisableWebhook(d.WebhookID, fmt.Sprintf("auto-disabled after %d consecutive failed deliveries", failCount))
			s.notifyWebhookDisabled(d.WebhookID)
		}
		return
	}
	// delay = min(cap, base·2^attempts) with full jitter. Compute in int64
	// nanoseconds throughout — an int() cast here truncated to a negative
	// value on 32-bit builds and panicked rand, killing the worker.
	backoff := int64(webhookBackoffBase) << uint(d.Attempts)
	if backoff > int64(webhookBackoffCap) || backoff <= 0 {
		backoff = int64(webhookBackoffCap)
	}
	jittered := time.Duration(randInt64(backoff))
	_ = s.st.RescheduleDelivery(d.ID, time.Now().Add(jittered).Unix(), code, errStr)
}

// notifyWebhookDisabled drops an inbox note to the owning agent, since the
// webhook itself is the broken channel.
func (s *Server) notifyWebhookDisabled(webhookID string) {
	agentID, err := s.st.AgentIDForWebhook(webhookID)
	if err != nil {
		return
	}
	a, err := s.st.AgentByID(agentID)
	if err != nil {
		return
	}
	_, _ = s.st.AddMessage(store.Message{
		AgentID: agentID, From: "system@" + s.st.Instance(), To: []string{a.Email},
		Subject: "A webhook was auto-disabled",
		Text:    "One of your webhook endpoints failed too many times in a row and has been disabled. Re-register it once it's healthy: POST /v1/webhooks.",
		DKIM:    "local", SPF: "local",
	})
	s.hub.notify(agentID)
}

// ---- registration API ----

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		URL        string `json:"url"`
		EventTypes string `json:"event_types"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if err := s.validateWebhookURL(req.URL); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	secret := newWebhookSecret()
	wh, err := s.st.CreateWebhook(agent.ID, req.URL, secret, req.EventTypes)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	// Secret is returned exactly once — the caller stores it to verify signatures.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": wh.ID, "url": wh.URL, "event_types": wh.EventTypes,
		"secret": secret,
		"note":   "store this secret; it verifies Webhook-Signature and is shown only now",
	})
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	whs, err := s.st.ListWebhooks(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]map[string]any, 0, len(whs))
	for _, wh := range whs {
		out = append(out, map[string]any{
			"id": wh.ID, "url": wh.URL, "event_types": wh.EventTypes,
			"enabled": wh.Enabled, "fail_count": wh.FailCount,
			"disabled_reason": wh.DisabledReason,
			"secret_hint":     "whsec_…" + lastN(wh.Secret, 4),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	if err := s.st.DeleteWebhook(agent.ID, r.PathValue("id")); err != nil {
		errJSON(w, http.StatusNotFound, "no such webhook")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("id")})
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
