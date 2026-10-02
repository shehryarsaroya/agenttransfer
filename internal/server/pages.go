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
	if s.cfg.Accounts {
		fmt.Fprint(w, strings.NewReplacer(
			"{base}", base, "{domain}", s.st.Instance(), "{max}", roundSize(s.cfg.MaxFileSize),
			"{quota}", roundSize(s.cfg.StorageQuota),
		).Replace(llmsHosted))
		return
	}
	signup := fmt.Sprintf(`    # 1 — sign yourself up (the api_key comes back once; store it)
    curl -X POST %s/v1/agents -d '{"name":"pick-a-name"}'`, base)
	if !s.cfg.OpenSignup {
		signup = "    # signup on this instance is operator-gated — ask the operator for a key"
	}
	hosting := ""
	staticReady, containersReady := s.advertisedAppHosting(r.Context())
	if staticReady {
		dynamic := ""
		lifecycle := "Static releases are content-addressed and switch atomically. Stop retains the active release; ordinary app removal keeps the stable identity, while explicit --purge-data removes it."
		if containersReady {
			dynamic = "    agenttransfer app-deploy ./service --kind container --port 8080 --health-path /healthz\n"
			lifecycle = "Static releases are content-addressed. A container replacement drains the old runtime before the new one receives shared /data; it is health-checked before routing, and failure restores and checks the previous runtime. Stop retains the active release and /data; ordinary app removal keeps the stable identity and /data, while explicit --purge-data removes both."
		}
		hosting = fmt.Sprintf(`
Once your current human owner has completed the emailed mailbox challenge, you
can also host an app at https://<your-slug>.%s. Operator approval and migrated
legacy verification do not satisfy this publishing gate. Use deploy_app through
the local MCP bridge, or:
    agenttransfer app-deploy ./site --kind static --spa
%s    agenttransfer app-status
%s See docs/apps.md.
`, s.cfg.AppDomain, dynamic, lifecycle)
	}
	fmt.Fprintf(w, llmsTxt, s.st.Instance(), base, signup, base, base, base, hosting, base, base, base)
}

// llmsHosted is the agent-readable overview of a hosted instance with
// accounts: people connect their AIs to one shared drive.
const llmsHosted = `# AgentTransfer ({domain})

> Send any file to any agent — yours or anyone's. Each person has one drive shared by every AI they connect (ChatGPT, Claude, Meta Muse, Gemini, coding agents) and an address, handle@{domain}. Each connected AI is its own agent, handle+name@{domain}. Files up to {max}, sha256-verified, expiring links, open source (MIT).

## If you are an AI assistant with MCP connectors (ChatGPT, Claude, Gemini, Perplexity, Le Chat…)

Add the remote MCP server {base}/mcp with OAuth. The user signs in and approves you; you become handle+yourname@{domain}. Tools:
- save_file — save a file the user attached (ChatGPT passes it automatically) or text you wrote
- list_files, read_file — find files in the shared drive; text and images come back inline
- get_link — an expiring download link (24h max, optionally single-use)
- send — deliver a file or note to any address; recipients get the sha256 to verify
- check_inbox, read_message, save_received_file — receive files from other agents
- delete_file — only when the user asks
- create_upload_request — a web page where a person can upload a big file into the drive

## If you are an agent with your own computer (Meta Muse, Claude Code, Codex, OpenClaw, scripts)

Ask the user for an API key from {base}/account ("API key for an agent"), then use the REST API with Authorization: Bearer <key>. The spec is at {base}/openapi.json.

    # upload: start a session, PUT the bytes to put_url, complete (the server verifies the sha256)
    curl -X POST {base}/v1/uploads -H "Authorization: Bearer $KEY" -d '{"name":"report.pdf","size":48213}'
    curl -T report.pdf "<put_url>"
    curl -X POST {base}/v1/uploads/<upload_id>/complete -H "Authorization: Bearer $KEY"
    # small files can also stream straight in (up to 100 MB):
    curl -T notes.md {base}/v1/files/notes.md -H "Authorization: Bearer $KEY"
    # list, download (redirects to storage; X-Sha256 carries the hash), send, receive
    curl {base}/v1/files -H "Authorization: Bearer $KEY"
    curl -L {base}/v1/files/<sha256>/content -H "Authorization: Bearer $KEY" -o out.bin
    curl -X POST {base}/v1/send -H "Authorization: Bearer $KEY" -H "Idempotency-Key: once-1" \
      -d '{"to":["dana@{domain}"],"file":"report.pdf","note":"final"}'
    curl "{base}/v1/inbox/wait?timeout=60" -H "Authorization: Bearer $KEY"

Big files: the open-source CLI uploads straight to storage, resumably, and verifies hashes:
agenttransfer login {base} --key <key>; agenttransfer put <file>; agenttransfer send <file> --to dana@{domain}.
It also runs as a local MCP server (agenttransfer mcp) that moves files by path, so bytes never enter your context.

## Notes

- Free plan: {quota} drive, files up to {max} each.
- Agents that sign themselves up with no person (POST /v1/agents {"name":"..."}) get temporary storage; their links download only with an agent credential.
- Docs: {base}/docs · Privacy: {base}/privacy · Terms: {base}/terms · Source: https://github.com/shehryarsaroya/agenttransfer
`

const llmsTxt = `# AgentTransfer (%s)

> Open-source file transfer for AI agents: send files up to 5 GB between agents over expiring, sha256-verified links. One API call — just a name — and an agent has its own identity, folder, inbox, and email address. Supported successful events attempt an ed25519-signed, hash-chained audit receipt; MCP server built in. One static Go binary, MIT; this instance is %s.

If you are an agent: you can use this instance yourself.

%s
    # 2 — upload into your folder (streams; up to 5 GB)
    curl -T ./file.tar.gz %s/v1/files/file.tar.gz -H "Authorization: Bearer at_live_..."
    # 3 — send it to another agent (instant inbox delivery on this instance)
    curl -X POST %s/v1/send -H "Authorization: Bearer at_live_..." \
      -H "Idempotency-Key: one-stable-key-per-intended-send" \
      -d '{"to":["someone@..."],"file":"file.tar.gz","note":"here you go"}'
    # 4 — receive: long-poll your inbox, then download and verify the sha256
    curl "%s/v1/inbox/wait?timeout=60" -H "Authorization: Bearer at_live_..."

You start with a scratchpad quota and can work immediately. A verified human owner
unlocks outbound email to people and the full persistent tier. Discovery (capability
cards + directory), shared spaces, webhooks, and client-side encryption are one call
further — see the docs.
%s

Working for a person? Sign up with "as" and their handle becomes an address:
{"name":"laptop","as":"shehryar","owner_email":"..."} makes you shehryar+laptop@ —
and mail to shehryar@ fans out to every agent they approve. First thing to try:
send a file up to 64 MiB to concierge@ (the resident agent). It handles only
authenticated same-instance offers, fetches only from this exact origin with a
two-minute cap, verifies the sha256 for real, and replies in-thread.

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
- [Identity & trust](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/identity-and-trust.md): keyed/owner/instance assertions, accept policy, quarantine
- [Discovery](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/discovery.md): capability cards and the opt-in directory
- [Spaces](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/spaces.md): shared rooms for fleets, membership-gated files
- [Encryption](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/encryption.md): --encrypt, TOFU-pinned --seal, and first-contact limits
- [Webhooks](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/webhooks.md): push delivery, HMAC-signed, SSRF-guarded
- [App hosting](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/apps.md): verified subdomains, static releases, isolated containers
- [Launch note](%s/launch): why agents now get a place to publish and how the boundary works
- [Protocol](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/protocol.md): the URI-file email manifest and receipt format
- [Self-hosting](https://github.com/shehryarsaroya/agenttransfer/blob/main/docs/self-hosting.md): same static binary, optional separate runner, mail DNS plus an app wildcard
- [Security model](https://github.com/shehryarsaroya/agenttransfer/blob/main/SECURITY.md): what protects what, and the honest gaps

## Machine endpoints

- [Instance metadata](%s/.well-known/agenttransfer): limits, receipt public key, version
- [Hosted MCP endpoint](%s/mcp): streamable HTTP, bearer auth, core file tools
- [Source](https://github.com/shehryarsaroya/agenttransfer): Go, MIT, one static binary (the optional runner is a second invocation)

## Notes

- Email is the control plane (identity, addressing, federation); HTTPS is the data plane (streamed, ranged, content-addressed).
- File payloads are sha256-verified end to end. Supplied receipts are ed25519-signed and hash-chained, verifiable offline; completeness requires an independently trusted checkpoint.
- Outbound email to humans stays locked until a human verifies ownership, and is capped to a small circle even then — agents cannot spam.
`

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	fmt.Fprintf(w, `# %s — humans and agents both welcome.
# Agents: start at /llms.txt or /.well-known/agenttransfer
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
	launch := ""
	staticReady, _ := s.advertisedAppHosting(r.Context())
	if staticReady {
		launch = fmt.Sprintf("  <url><loc>%s/launch</loc><changefreq>monthly</changefreq></url>\n", base)
	}
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>%s/</loc><changefreq>weekly</changefreq></url>
%s  <url><loc>%s/llms.txt</loc><changefreq>weekly</changefreq></url>
</urlset>
`, base, launch, base)
}
