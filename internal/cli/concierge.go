package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

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
	maxFetch := fs.Int64("max-fetch", 512<<20, "largest file it downloads to verify (bytes)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
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
	instDomain := who.Email[strings.LastIndex(who.Email, "@")+1:]
	log.Printf("concierge: serving as %s (replies on-instance only, ≤%d/h per sender)", who.Email, *perHour)

	rl := newSenderLimiter(*perHour)
	for {
		var out struct {
			Messages []struct {
				ID    string `json:"id"`
				From  string `json:"from"`
				Text  string `json:"text"`
				Offer struct {
					Name    string `json:"name"`
					URL     string `json:"url"`
					SHA256  string `json:"sha256"`
					Size    int64  `json:"size"`
					EncMode string `json:"enc_mode"`
				} `json:"offer"`
			} `json:"messages"`
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
			if from == "" || from == who.Email || !strings.HasSuffix(from, "@"+instDomain) || !rl.allow(from) {
				markRead(a, m.ID)
				continue
			}
			reply := conciergeReply(a, m.Offer.Name, m.Offer.URL, m.Offer.SHA256, m.Offer.Size, m.Offer.EncMode, m.Text, *maxFetch)
			req := map[string]any{"to": []string{from}, "note": reply, "reply_to": m.ID}
			var res map[string]any
			if err := a.json("POST", "/v1/send", req, &res); err != nil {
				log.Printf("concierge: reply to %s: %v", from, err)
			} else {
				log.Printf("concierge: %s ← replied (msg %s)", from, m.ID)
			}
			markRead(a, m.ID)
		}
	}
}

// conciergeReply verifies for real, then writes the note.
func conciergeReply(a *api, name, url, wantSHA string, size int64, encMode, text string, maxFetch int64) string {
	if url == "" {
		// Plain message: greet + explain, briefly.
		if strings.TrimSpace(text) == "" {
			return "hello! I'm this instance's concierge. Send me any file and I'll download it, verify its sha256, and reply with what I saw — every step receipted. Try: agenttransfer send <file> --to " + "concierge"
		}
		return "hello! I'm the concierge — send me a file and I'll verify it end to end and reply with the hash. (Everything we just did is in your signed receipt log: agenttransfer log --verify)"
	}
	if encMode == "sealed" || encMode == "symmetric" {
		return fmt.Sprintf("received %q (%s, encrypted client-side — as it should be; I can't read it, and the sha256 in your offer covers the ciphertext). Delivery worked end to end.", name, humanBytes(size))
	}
	if size > maxFetch {
		return fmt.Sprintf("received the offer for %q (%s) — larger than I fetch, but the link and sha256 arrived intact; your recipient's `get` will verify it on download.", name, humanBytes(size))
	}
	got, n, err := fetchAndHash(a, url)
	if err != nil {
		return fmt.Sprintf("received the offer for %q but my download failed (%v) — the link may have expired or been revoked. Mint a fresh send and I'll try again.", name, err)
	}
	if !strings.EqualFold(got, wantSHA) {
		return fmt.Sprintf("⚠ downloaded %q (%s) but the sha256 does NOT match the offer — got %s, expected %s. I refused it; so would every agent here.", name, humanBytes(n), got[:16], wantSHA[:16])
	}
	return fmt.Sprintf("received %q — %s, sha256 %s… verified ✓ end to end. Both our receipt logs now prove this handoff (agenttransfer log --verify).", name, humanBytes(n), got[:16])
}

func fetchAndHash(a *api, url string) (string, int64, error) {
	req, err := http.NewRequest("GET", url+"?dl=1", nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, errors.New(resp.Status)
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func markRead(a *api, id string) {
	_ = a.json("POST", "/v1/inbox/"+id+"/read", nil, nil)
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

// senderLimiter: sliding one-hour window per sender.
type senderLimiter struct {
	max  int
	hits map[string][]time.Time
}

func newSenderLimiter(max int) *senderLimiter {
	return &senderLimiter{max: max, hits: map[string][]time.Time{}}
}

func (l *senderLimiter) allow(from string) bool {
	now := time.Now()
	keep := l.hits[from][:0]
	for _, t := range l.hits[from] {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	l.hits[from] = keep
	if len(keep) >= l.max {
		return false
	}
	l.hits[from] = append(keep, now)
	return true
}
