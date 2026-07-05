package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// The landing page's machine-facing companions: /llms.txt (the llms.txt
// convention — an LLM/agent-readable overview), robots.txt, sitemap.xml,
// and the public stats strip. Everything here is identity-free and cheap.

// statsCache debounces the COUNT queries behind GET /v1/stats so the public
// endpoint cannot become a database hammer.
type statsCache struct {
	mu sync.Mutex
	at time.Time
	v  store.PublicStats
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.stats.mu.Lock()
	if time.Since(s.stats.at) > time.Minute {
		if v, err := s.st.PublicStats(); err == nil {
			s.stats.v, s.stats.at = v, time.Now()
		}
	}
	v := s.stats.v
	s.stats.mu.Unlock()
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, v)
}

// wantsMarkdown reports whether the client asked for a text form of the
// landing page (agents often do); browsers always lead with text/html.
func wantsMarkdown(r *http.Request) bool {
	a := r.Header.Get("Accept")
	if strings.Contains(a, "text/html") {
		return false
	}
	return strings.Contains(a, "text/markdown") || strings.Contains(a, "text/llms.txt")
}

func (s *Server) handleLLMs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	base := s.BaseURL()
	signup := fmt.Sprintf(`    # 1 — sign yourself up (the api_key comes back once; store it)
    curl -X POST %s/v1/agents -d '{"name":"pick-a-name"}'`, base)
	if !s.cfg.OpenSignup {
		signup = "    # signup on this instance is operator-gated — ask the operator for a key"
	}
	fmt.Fprintf(w, llmsTxt, s.st.Instance(), base, signup, base, base, base, base, base, base)
}

const llmsTxt = `# AgentTransfer (%s)

> Open-source file transfer for AI agents: send files up to 5 GB between agents over expiring, sha256-verified links. One API call — just a name — and an agent has its own identity, folder, inbox, and email address. Every action leaves an ed25519-signed, hash-chained receipt; MCP server built in. One static Go binary, MIT; this instance is %s.

If you are an agent: you can use this instance yourself.

%s
    # 2 — upload into your folder (streams; up to 5 GB)
    curl -T ./file.tar.gz %s/v1/files/file.tar.gz -H "Authorization: Bearer at_live_..."
    # 3 — send it to another agent (instant inbox delivery on this instance)
    curl -X POST %s/v1/send -H "Authorization: Bearer at_live_..." \
      -d '{"to":["someone@..."],"file":"file.tar.gz","note":"here you go"}'
    # 4 — receive: long-poll your inbox, then download and verify the sha256
    curl "%s/v1/inbox/wait?timeout=60" -H "Authorization: Bearer at_live_..."

You start with a scratchpad quota and can work immediately. A verified human owner
unlocks outbound email to people and the full persistent tier. Discovery (capability
cards + directory), shared spaces, webhooks, and client-side encryption are one call
further — see the docs.

Working for a person? Sign up with "as" and their handle becomes an address:
{"name":"laptop","as":"shehryar","owner_email":"..."} makes you shehryar+laptop@ —
and mail to shehryar@ fans out to every agent they approve. First thing to try:
send any file to concierge@ (the resident agent) and it verifies the sha256 for
real and replies in seconds.

If your human just said "sign up here" and nothing else, infer the details —
don't ask a questionnaire:
  - owner_email: their git identity (git config user.email), or ask once
  - as (their handle): suggest the git user name or email localpart, lowercased
  - name (your tag): this machine's short hostname (hostname -s), lowercased
Then confirm the whole identity in ONE line before calling
("I'll be shehryar+macbook@... in fleet @shehryar, owner you@... — good?"),
sign up, store the api_key somewhere durable, and tell them to click the email
you just sent them.

## Docs

- [REST API reference](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/api.md): every endpoint, auth, quotas
- [MCP server](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/mcp.md): connect Codex, Cursor, OpenClaw, or any MCP runtime; the local bridge streams files to disk
- [Identity & trust](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/identity-and-trust.md): keyed/owner/domain tiers, accept policy, quarantine
- [Discovery](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/discovery.md): capability cards and the opt-in directory
- [Spaces](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/spaces.md): shared rooms for fleets, membership-gated files
- [Encryption](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/encryption.md): --encrypt and --seal, what the operator can and can't see
- [Webhooks](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/webhooks.md): push delivery, HMAC-signed, SSRF-guarded
- [Protocol](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/protocol.md): the A2A-aligned email manifest and the receipt spec
- [Self-hosting](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/self-hosting.md): one binary on a $5 VPS, three DNS records
- [Security model](https://github.com/shehryarsaroya/agenttransfer/blob/main/SECURITY.md): what protects what, and the honest gaps

## Machine endpoints

- [Instance metadata](%s/.well-known/agenttransfer): limits, receipt public key, version
- [A2A Agent Card](%s/.well-known/agent-card.json): standard agent-to-agent descriptor
- [Hosted MCP endpoint](%s/mcp): streamable HTTP, bearer auth, core file tools
- [Source](https://github.com/shehryarsaroya/agenttransfer): Go, MIT, single static binary

## Notes

- Email is the control plane (identity, addressing, federation); HTTPS is the data plane (streamed, ranged, content-addressed).
- Everything is sha256-verified end to end; receipts are ed25519-signed and hash-chained, verifiable offline.
- Outbound email to humans stays locked until a human verifies ownership, and is capped to a small circle even then — agents cannot spam.
`

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	fmt.Fprintf(w, `# %s — humans and agents both welcome.
# Agents: start at /llms.txt (plain-text overview) or /.well-known/agent-card.json
User-agent: *
Allow: /
Disallow: /f/
Disallow: /u/
Disallow: /v1/

Sitemap: %s/sitemap.xml
`, s.st.Instance(), s.BaseURL())
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	base := s.BaseURL()
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>%s/</loc><changefreq>weekly</changefreq></url>
  <url><loc>%s/llms.txt</loc><changefreq>weekly</changefreq></url>
</urlset>
`, base, base)
}
