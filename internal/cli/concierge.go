package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const conciergeFetchTimeout = 2 * time.Minute

type conciergeMessage struct {
	ID          string `json:"id"`
	From        string `json:"from"`
	Text        string `json:"text"`
	DKIM        string `json:"dkim"`
	Quarantined bool   `json:"quarantined"`
	Sender      struct {
		DomainVerified bool `json:"domain_verified"`
	} `json:"sender"`
	Offer struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
		EncMode string `json:"enc_mode"`
		Trusted bool   `json:"trusted"`
	} `json:"offer"`
}

// cmdConcierge runs the instance's resident agent: everyone's first
// counterparty. It long-polls its own inbox and answers every arrival in
// thread — for files it actually downloads the bytes and verifies the sha256
// before saying so, because the reply IS the product demo. It never contacts
// anyone unprompted, never emails humans, only replies on-instance, and
// rate-caps per sender. Run it against a normal agent account:
//
//	agenttransfer login https://instance --key at_live_...
//	agenttransfer concierge
func cmdConcierge(args []string) error {
	fs := flag.NewFlagSet("concierge", flag.ExitOnError)
	perHour := fs.Int("per-sender", 30, "max replies per sender per hour")
	maxFetch := fs.Int64("max-fetch", 64<<20, "largest file it downloads to verify (bytes)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *maxFetch <= 0 || *maxFetch == math.MaxInt64 {
		return fmt.Errorf("--max-fetch must be between 1 and %d bytes", int64(math.MaxInt64-1))
	}
	if *perHour <= 0 {
		return errors.New("--per-sender must be greater than zero")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var who struct {
		Email    string `json:"email"`
		Instance string `json:"instance"`
	}
	if err := a.json("GET", "/v1/whoami", nil, &who); err != nil {
		return err
	}
	log.Printf("concierge: serving as %s (replies on-instance only, ≤%d/h per sender)", who.Email, *perHour)

	rl := newSenderLimiter(*perHour)
	fetchClient := newConciergeHTTPClient(a.base)
	for {
		pollStarted := time.Now()
		var out struct {
			Messages []conciergeMessage `json:"messages"`
		}
		if err := a.json("GET", "/v1/inbox/wait?timeout=50", nil, &out); err != nil {
			log.Printf("concierge: inbox: %v (retrying)", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for _, m := range out.Messages {
			// Reply only to agents on this instance; never off-instance, never
			// to self, and never beyond the per-sender budget (silent drop —
			// an error reply would itself be spammable).
			from := strings.ToLower(strings.TrimSpace(m.From))
			if !conciergeAllows(m, who.Email, who.Instance) || !rl.allow(from, m.ID) {
				markRead(a, m.ID)
				continue
			}
			reply := conciergeReply(fetchClient, a.base, m.Offer.Name, m.Offer.URL, m.Offer.SHA256, m.Offer.Size, m.Offer.EncMode, m.Text, *maxFetch)
			if err := replyAndMarkRead(a, m, reply); err != nil {
				log.Printf("concierge: reply to %s: %v", from, err)
				// Keep the message unread. The next poll retries with the same
				// idempotency key, so an uncertain response cannot either duplicate
				// the reply or silently lose it.
				continue
			}
			log.Printf("concierge: %s ← replied (msg %s)", from, m.ID)
		}
		// A conforming long-poll normally consumes 50 seconds. Still enforce a
		// floor defensively: an older/misconfigured server or proxy that returns
		// an immediate empty response must not turn this resident client into a
		// tight authenticated request loop.
		if delay := time.Second - time.Since(pollStarted); delay > 0 {
			time.Sleep(delay)
		}
	}
}

// replyAndMarkRead keeps the reply and inbox acknowledgement in retry-safe
// order. If the send succeeds but the mark-read call fails, the next poll
// replays the same stored send result and tries the acknowledgement again.
func replyAndMarkRead(a *api, m conciergeMessage, reply string) error {
	req := map[string]any{"to": []string{strings.ToLower(strings.TrimSpace(m.From))}, "note": reply, "reply_to": m.ID}
	var res map[string]any
	if err := a.jsonIdempotent("/v1/send", req, &res, "concierge-"+m.ID); err != nil {
		return err
	}
	return a.json("POST", "/v1/inbox/"+url.PathEscape(m.ID)+"/read", nil, nil)
}

// conciergeAllows requires provenance produced by local server delivery, not
// a spoofable From suffix. The redundant sender/offer trust fields fail closed
// against an older or malformed API response.
func conciergeAllows(m conciergeMessage, self, instance string) bool {
	from := strings.ToLower(strings.TrimSpace(m.From))
	_, domain, ok := splitAddr(from)
	if m.ID == "" || !ok || from == strings.ToLower(strings.TrimSpace(self)) || domain != strings.ToLower(strings.TrimSpace(instance)) {
		return false
	}
	if m.Quarantined || !strings.EqualFold(strings.TrimSpace(m.DKIM), "local") || !m.Sender.DomainVerified {
		return false
	}
	return m.Offer.URL == "" || m.Offer.Trusted
}

// conciergeReply verifies for real, then writes the note.
func conciergeReply(client *http.Client, allowedOrigin, name, rawURL, wantSHA string, size int64, encMode, text string, maxFetch int64) string {
	if rawURL == "" {
		// Plain message: greet + explain, briefly.
		if strings.TrimSpace(text) == "" {
			return "hello! I'm this instance's concierge. Send me any file and I'll download it, verify its sha256, and reply with what I saw. Supported transfer steps also attempt signed audit receipts. Try: agenttransfer send <file> --to " + "concierge"
		}
		return "hello! I'm the concierge — send me a file and I'll verify it end to end and reply with the hash. Supported transfer steps attempt signed audit receipts; inspect yours with: agenttransfer log --verify"
	}
	if encMode == "sealed" || encMode == "symmetric" {
		return fmt.Sprintf("received %q (%s, encrypted client-side — as it should be; I can't read it, and the sha256 in your offer covers the ciphertext). Delivery worked end to end.", name, humanBytes(size))
	}
	if size > maxFetch {
		return fmt.Sprintf("received the offer for %q (%s) — larger than I fetch, but the link and sha256 arrived intact; your recipient's `get` will verify it on download.", name, humanBytes(size))
	}
	wantSHA, err := validSHA256(wantSHA)
	if err != nil {
		return fmt.Sprintf("received the offer for %q but it carried an invalid sha256; I refused it without downloading (%v).", name, err)
	}
	got, n, err := fetchAndHash(client, allowedOrigin, rawURL, maxFetch)
	if err != nil {
		return fmt.Sprintf("received the offer for %q but my download failed (%v) — the link may have expired or been revoked. Mint a fresh send and I'll try again.", name, err)
	}
	if !strings.EqualFold(got, wantSHA) {
		return fmt.Sprintf("⚠ downloaded %q (%s) but the sha256 does NOT match the offer — got %s, expected %s. I refused it; so would every agent here.", name, humanBytes(n), shortDigest(got), shortDigest(wantSHA))
	}
	return fmt.Sprintf("received %q — %s, sha256 %s… verified ✓ end to end. Supported handoff steps attempt signed audit receipts (agenttransfer log --verify).", name, humanBytes(n), shortDigest(got))
}

func validSHA256(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "sha256:")))
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("expected exactly 64 hexadecimal characters")
	}
	return raw, nil
}

func shortDigest(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}

func fetchAndHash(client *http.Client, allowedOrigin, rawURL string, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return "", 0, errors.New("invalid download byte limit")
	}
	u, err := validateConciergeURL(rawURL, allowedOrigin)
	if err != nil {
		return "", 0, err
	}
	q := u.Query()
	q.Set("dl", "1")
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, errors.New(resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return "", 0, fmt.Errorf("response declares %d bytes, above the %d-byte limit", resp.ContentLength, maxBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", n, err
	}
	if n > maxBytes {
		return "", n, fmt.Errorf("response exceeded the %d-byte limit", maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func validateConciergeURL(raw, allowedOrigin string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid download URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("download URL must use http or https")
	}
	if u.Hostname() == "" || u.Opaque != "" {
		return nil, errors.New("download URL has no valid host")
	}
	if u.User != nil {
		return nil, errors.New("download URL must not contain credentials")
	}
	if !sameOrigin(u.String(), allowedOrigin) {
		return nil, fmt.Errorf("download URL must use the configured instance origin %s", normalizedBase(allowedOrigin))
	}
	allowLoopback := configuredLoopbackOrigin(allowedOrigin)
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !conciergePublicUnicast(ip) && !(allowLoopback && ip.Unmap().IsLoopback()) {
		return nil, fmt.Errorf("download URL targets non-public address %s", ip)
	}
	u.Fragment = ""
	return u, nil
}

var conciergeExtraDenyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // current network / self-identification
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.31.196.0/24"), // AS112 service
	netip.MustParsePrefix("192.52.193.0/24"), // AMT
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("192.175.48.0/24"), // AS112 service
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),       // reserved / limited broadcast
	netip.MustParsePrefix("64:ff9b::/96"),      // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),    // local-use NAT64 prefix
	netip.MustParsePrefix("100::/64"),          // discard-only
	netip.MustParsePrefix("100:0:0:1::/64"),    // dummy prefix
	netip.MustParsePrefix("::/96"),             // IPv4-compatible IPv6
	netip.MustParsePrefix("2001::/23"),         // special-purpose protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),     // documentation
	netip.MustParsePrefix("2002::/16"),         // 6to4
	netip.MustParsePrefix("3fff::/20"),         // documentation
	netip.MustParsePrefix("5f00::/16"),         // segment-routing SIDs
	netip.MustParsePrefix("fec0::/10"),         // deprecated site-local unicast
	netip.MustParsePrefix("2620:4f:8000::/48"), // AS112 service
}

func conciergePublicUnicast(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range conciergeExtraDenyPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func conciergeDialControl(allowLoopback bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
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
		if !conciergePublicUnicast(ip) && !(allowLoopback && ip.Unmap().IsLoopback()) {
			return fmt.Errorf("blocked non-public address %s", ip)
		}
		return nil
	}
}

func configuredLoopbackOrigin(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

func newConciergeHTTPClient(allowedOrigin string) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: conciergeDialControl(configuredLoopbackOrigin(allowedOrigin))}
	return &http.Client{
		Timeout: conciergeFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

func markRead(a *api, id string) {
	_ = a.json("POST", "/v1/inbox/"+url.PathEscape(id)+"/read", nil, nil)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

type senderHit struct {
	messageID string
	at        time.Time
}

// senderLimiter is a sliding one-hour window per sender. A retry of the same
// message reuses its admission rather than spending another reply slot.
type senderLimiter struct {
	max       int
	hits      map[string][]senderHit
	lastPrune time.Time
}

func newSenderLimiter(max int) *senderLimiter {
	return &senderLimiter{max: max, hits: map[string][]senderHit{}}
}

func (l *senderLimiter) allow(from, messageID string) bool {
	now := time.Now()
	if l.lastPrune.IsZero() || now.Sub(l.lastPrune) >= time.Minute || len(l.hits) > 1024 {
		for sender, hits := range l.hits {
			keep := hits[:0]
			for _, hit := range hits {
				if now.Sub(hit.at) < time.Hour {
					keep = append(keep, hit)
				}
			}
			if len(keep) == 0 {
				delete(l.hits, sender)
			} else {
				l.hits[sender] = keep
			}
		}
		l.lastPrune = now
	}
	keep := l.hits[from][:0]
	for _, hit := range l.hits[from] {
		if now.Sub(hit.at) < time.Hour {
			keep = append(keep, hit)
		}
	}
	l.hits[from] = keep
	for _, hit := range keep {
		if hit.messageID == messageID {
			return true
		}
	}
	if len(keep) >= l.max {
		return false
	}
	l.hits[from] = append(keep, senderHit{messageID: messageID, at: now})
	return true
}
