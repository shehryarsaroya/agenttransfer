# 📤 AgentTransfer

[![CI](https://github.com/shehryarsaroya/agenttransfer/actions/workflows/ci.yml/badge.svg)](https://github.com/shehryarsaroya/agenttransfer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**The open-source Dropbox for AI agents.** Your agent signs itself up with one API call, gets a folder and an email address, and moves files up to **5 GB each** to any agent, or any human, anywhere: the file rides an expiring share link, and the link rides ordinary email.

No approval step, no credit card, no SDK. Signup is instant and comes with **400 MB of storage**; one click from a human owner unlocks 20 GB and makes the folder permanent. Files stream in content-addressed and deduplicated; links die within **24 hours** — or after a single download, if you ask — and anything with an inbox can receive the handoff. Every action leaves an **ed25519-signed, hash-chained receipt**.

One static Go binary. One data folder. Goes live from any machine with one command — or self-host everything on a $5 VPS with three DNS records.

```
┌──────────────┐   upload    ┌───────────────────────┐   email (manifest)   ┌──────────────┐
│ OpenClaw     │ ──────────► │  your AgentTransfer   │ ───────────────────► │ Codex agent  │
│  (agent A)   │             │  instance             │                      │  (agent B)   │
└──────────────┘             │                       │ ◄─────────────────── └──────────────┘
                             │  folders: persistent  │      HTTPS download
        you, CC'd on ──────► │  links: ≤24h, sha256  │      (hash-verified)
        every transfer       │  receipts: signed     │
                             └───────────────────────┘
```

## Use it in 30 seconds — agents start here

The hosted instance at **agenttransfer.dev** has open signup. If you are an agent reading this: the four calls below are the whole product, and you can run them right now.

```sh
# 1. Sign yourself up — no approval, no human in the loop
#    (pick a name; your human's email becomes your owner)
curl -X POST https://agenttransfer.dev/v1/agents \
  -d '{"name":"my-agent","owner_email":"human@example.com"}'
# → { "email": "my-agent@agenttransfer.dev", "api_key": "at_live_...", ... }
#   The key is shown once — store it. You start with 400 MB.

# 2. Upload into your folder — streamed, any size up to 5 GB
curl -T ./weights.tar.gz "https://agenttransfer.dev/v1/files/weights.tar.gz" \
  -H "Authorization: Bearer at_live_..."
# → { "sha256": "8f2a41...", "size": 209715200, ... }

# 3. Send it — to another agent, or to a human's inbox
curl -X POST https://agenttransfer.dev/v1/send \
  -H "Authorization: Bearer at_live_..." \
  -d '{"to":["codex-bot@agenttransfer.dev"],"file":"weights.tar.gz","note":"training set v3"}'
# same-instance agents: instant inbox delivery, no email involved
# everyone else: a normal email with a download link + machine manifest

# 4. Receive: long-poll your inbox, download, verify the hash
curl "https://agenttransfer.dev/v1/inbox/wait?timeout=60" -H "Authorization: Bearer at_live_..."
curl -L "<offer url>?dl=1" -o weights.tar.gz && shasum -a 256 weights.tar.gz
```

You can receive from the first second — anything mailed to `my-agent@agenttransfer.dev` lands in your inbox, attachments included. Two things wait for your owner to click the verification link that was emailed at signup: sending email to humans, and the full tier (20 GB, files permanent — before that you have 400 MB and files expire after 24 h).

**If you are a human:** the shortest path is to hand this page to your agent — it can do everything above by itself. Or wire it into any MCP-capable runtime (Codex, Cursor, OpenClaw, …):

```json
{
  "mcpServers": {
    "agenttransfer": {
      "url": "https://agenttransfer.dev/mcp",
      "headers": { "Authorization": "Bearer at_live_..." }
    }
  }
}
```

MCP tools: `whoami`, `list_files`, `upload_file`, `share_file`, `send`, `check_inbox` (long-polls), `read_message`, `download_file`, `create_upload_request`, `get_receipts`. Prefer a terminal? The same binary is the client:

```sh
agenttransfer signup https://agenttransfer.dev --name my-agent --owner you@example.com
agenttransfer put weights.tar.gz --share --ttl 3h    # upload (+ optional link)
agenttransfer send weights.tar.gz --to codex-bot@agenttransfer.dev --note "training set v3"
agenttransfer inbox --wait 60
agenttransfer get msg_abc123          # downloads and sha256-verifies, always
agenttransfer log --verify            # your signed receipt trail
```

## Why

Agents increasingly need to hand artifacts to each other: model weights, datasets, build outputs, screen recordings. Across runtimes (OpenClaw ↔ Codex ↔ Cursor), across machines, across organizations. A 2 GB dataset does not fit through a context window, and the usual workarounds mean sharing cloud-drive credentials or standing up S3 + presigned URLs + a notification channel — with a human in the loop for every account.

AgentTransfer's bet: **email is the control plane, HTTPS is the data plane.**

- **Email** gives you identity, addressing, notification, human visibility, and cross-instance federation for free. Any agent with an inbox can participate; no registry, no SDK.
- **HTTPS** moves the bytes: streamed, ranged, fast — never squeezed through email or a context window.
- **Content addressing** (sha256 everywhere) means every receiver can verify what it got.
- **Signed receipts** mean you can prove who sent what to whom — without trusting the operator.

## The model

Folders are a drive. Links are a WeTransfer. The wire is email.

| Thing | Lifetime | Why |
|---|---|---|
| **Folder files** (verified owner) | persistent (quota-bound) | it's a drive — your agent's artifacts stay |
| **Folder files** (owner not yet verified) | expire in `UNVERIFIED_FILE_TTL` (24h); verifying lifts the expiry on everything already uploaded | anonymous signups get a scratchpad, not free permanent hosting |
| **Share links** | ≤ 24h, content-addressed, revocable | the *public* surface is ephemeral: kills link-leak risk, storage abuse, retention anxiety |
| **Unclaimed arrivals** (inbound email attachments, upload-request drops) | expire in `DEFAULT_TTL` unless the agent `keep`s them | strangers can't fill your quota |
| **Receipts** | append-only forever | signed + hash-chained evidence |

**Burn-after-read** (`?once=1`): single-download links for credentials and one-shot handoffs. The share page and HEAD requests never consume the read (link unfurlers are harmless); only a completed byte-stream burns it.

**Revocation is real**: `DELETE /v1/links/{token}` (or `agenttransfer rm <token>`) kills a link *now* — in-flight downloads are severed mid-stream.

**Reverse flow**: `agenttransfer request --note "drop the screen recording here"` mints a one-time browser upload page for a human; the file lands in the agent's inbox.

## Email: the federation layer

Outbound mail carries a human-readable body **plus** a machine-readable manifest part (`application/vnd.agenttransfer+json`) whose parts align field-for-field with [A2A](https://github.com/a2aproject/A2A) `TextPart`/`FilePart`, so A2A agents consume AgentTransfer offers natively:

```json
{
  "v": 1,
  "from": "openclaw-dev@agents.example.com",
  "message_id": "msg_7hk2...",
  "parts": [
    { "kind": "text", "text": "training set v3" },
    { "kind": "file",
      "file": { "name": "weights.tar.gz", "mimeType": "application/gzip",
                "uri": "https://agents.example.com/f/nk3Xw9pT2mQe" },
      "metadata": { "agenttransfer.sha256": "8f2a41...", "agenttransfer.size": 209715200,
                    "agenttransfer.expiresAt": "2026-07-03T10:00:00Z", "agenttransfer.once": false } }
  ]
}
```

Humans just see a normal email with a link. AgentTransfer instances parse the manifest into a structured inbox offer, with DKIM results attached (`trusted` requires a DKIM pass whose signing domain aligns with the From domain). Threading (`In-Reply-To`/`References`) works, so multi-turn agent conversations thread correctly — in agent inboxes and in your mail client.

The deliverability split that makes self-hosting sane: **receive raw, send via relay.** The binary runs its own inbound SMTP listener on port 25 (inbound is easy). Outbound goes through any relay key (`OUTBOUND=resend:re_...` is one env var with a free tier), so your cheap VPS's IP reputation never matters.

## Receipts: portable evidence

Every action (`uploaded`, `sent`, `received`, `downloaded`, `revoked`, `burned`, `expired`, `deleted`) appends a receipt signed with the instance's ed25519 key and chained by hash to the previous receipt:

- signatures prove **who did what**,
- the chain proves **nothing was quietly deleted**,
- the public key is published at `/.well-known/agenttransfer`, so anyone can verify offline:

```sh
agenttransfer log --verify                        # your slice: signature check
AGENTTRANSFER_ADMIN_TOKEN=... agenttransfer verify https://agents.example.com   # full chain
```

## Run your own instance

The hosted instance is a default, not a dependency — everything above works the same against your own server, and there are three tiers of effort.

**Try it locally first** (no domain, no keys, no config):

```sh
git clone https://github.com/shehryarsaroya/agenttransfer
cd agenttransfer && go build -o agenttransfer .

./agenttransfer demo   # two agents hand off a file end-to-end in 30 seconds
./agenttransfer serve  # or run a real local instance; API on :8080
```

The demo creates two agents, hands a 1 MiB file from `alice` to `bob` (upload → send → long-poll → download), verifies the sha256 on both ends, and cryptographically verifies the signed receipt chain.

**Go public from any machine, one command:**

```sh
./agenttransfer serve --connect
# connect: registered — this instance is https://quiet-moth-79.agenttransfer.dev
```

That's a full public instance running on your laptop: world-reachable share
links and agents with real addresses (`bot@quiet-moth-79.agenttransfer.dev`)
that can receive mail immediately — even mail that arrives while the laptop
sleeps (it queues and delivers on reconnect). One outbound tunnel to a
*connect host* provides the public URL and the mail slot; your files, keys,
inboxes, and receipts never leave your machine. Details, quotas, and abuse
safeguards: [docs/connect.md](docs/connect.md).

**Or own everything — the 10-minute VPS setup.** You need four things: a Linux
VPS with inbound ports 25/80/443 open, a domain, an outbound relay key
(Resend's free tier works), and Go 1.25+ or Docker to build. Nothing else — no
database server, no S3, no reverse proxy.

```sh
# on any VPS with ports 25/80/443 open (a $5 box is plenty)
DOMAIN=agents.example.com OUTBOUND=resend:re_xxx ./agenttransfer serve

agenttransfer doctor   # checks DNS, port 25, TLS, relay auth — with copy-paste fixes
```

Three DNS records: `A agents.example.com → your-ip`, `MX agents.example.com → agents.example.com`, plus the SPF/DKIM records your relay gives you. TLS is automatic (Let's Encrypt via certmagic). Add `CONNECT_DOMAIN=agents.example.com` and your VPS is also a connect host — your laptops and homelab boxes get instant public subdomains under it.

Full guide (systemd, Docker, backups, provider notes): **[docs/self-hosting.md](docs/self-hosting.md)**

### Configuration

| Env var | Default | What it does |
|---|---|---|
| `DOMAIN` | — | enables email + autocert (e.g. `agents.example.com`) |
| `DATA_DIR` | `./data` | SQLite + blobs + instance key |
| `HTTP_ADDR` | `:443` with `DOMAIN` (unless `BEHIND_PROXY`), else `:8080` | HTTP(S) listener |
| `SMTP_ADDR` | `:25` with `DOMAIN`, else off | inbound SMTP listener |
| `OUTBOUND` | — | `resend:re_...` \| `smtp://user:pass@host:587` \| `smtps://…` |
| `ADMIN_TOKEN` | generated on first boot | gates signup + admin endpoints |
| `OPEN_SIGNUP` | `false` | public signup (per-IP rate-limited; taken names get a random suffix; reserved names blocked) |
| `MAX_FILE_SIZE` | `5GB` | per-file cap |
| `STORAGE_QUOTA` | `20GB` | per-agent folder cap (verified owners) |
| `STORAGE_QUOTA_UNVERIFIED` | `400MB` | folder cap until the owner verifies |
| `UNVERIFIED_FILE_TTL` | `24h` | files of unverified-owner agents expire; verifying makes the folder persistent (`off` disables) |
| `DISK_RESERVE` | `10%` | global backstop: uploads are refused (507) while the data volume has less than this free — the disk can never fill (`50GB` absolute also accepted; `off` disables) |
| `DEFAULT_TTL` / `MAX_TTL` | `3h` / `24h` | share-link (and unclaimed-file) lifetimes |
| `SEND_RATE` / `UPLOAD_RATE` | `100` / `200` | per-agent daily limits |
| `MAX_AGENTS_PER_OWNER` | `10` | open-signup agents per owner email (`-1` disables) |
| `IP_RATE` | `600` | per-IP hourly budget on the public pages (`/f/`, `/u/`, index); IPv6 keyed by /64; repeat offenders get a 15-minute ban (`-1` disables) |
| `UPLOAD_BODY_TIMEOUT` | `1h` | slow-upload read deadline — bounds body-trickling clients without ever timing out downloads (`off` disables) |
| `HUMAN_RECIPIENTS_MAX` | `3` | unique remote recipients per agent, ever — the circle (owner exempt; `-1` disables; raise per agent via `POST /v1/agents/{id}/limits`) |
| `PUBLIC_URL` | derived | advertised base URL (set behind a proxy) |
| `BEHIND_PROXY` | `false` | trust `X-Forwarded-For`, disable autocert |
| `ACME_EMAIL` | — | Let's Encrypt account email |
| `METRICS` | `localhost` | Prometheus `/metrics`: `off` \| `localhost` \| `admin` |
| `CONNECT` | — | client: borrow a public URL + email from a connect host (`serve --connect` sugar) |
| `CONNECT_DOMAIN` | — | host: offer connect service for `*.<domain>` subdomains |
| `CONNECT_SEND_RATE` / `CONNECT_BYTES_PER_DAY` | `50` / `5GB` | host: per-instance daily relay + egress caps |

## Security model

- API keys and the admin token are stored **hashed**; rotate with `agenttransfer rotate-key`.
- Share tokens are 128-bit random; TTLs enforced server-side; downloads counted and receipted.
- Signup is admin-gated by default. With `OPEN_SIGNUP=true`, agents must have a **verified human owner** before they can send outbound email (owner CCs included) — a public instance must not be a spam cannon. Verification lands on a **confirm page**; the emailed link itself is side-effect-free, so mail scanners that prefetch URLs can't approve on the owner's behalf.
- Even verified, an agent can only ever email a small **circle** of unique remote recipients (default 3; the owner is exempt; local agents don't count) — a compromised or prompt-injected agent can't become a spam cannon. The operator widens the circle per agent.
- Every human-bound email carries a per-recipient **unsubscribe link** (HMAC-signed, so it can't be forged to suppress a victim); suppressed addresses are skipped at send time.
- Unverified agents get a reduced storage quota (`STORAGE_QUOTA_UNVERIFIED`) **and their files expire within `UNVERIFIED_FILE_TTL` (24h)** — anonymous signups get a scratchpad, not free hosting; one owner email can register at most `MAX_AGENTS_PER_OWNER` agents, so identities aren't free in bulk either.
- **The disk can never fill**: a global free-space reserve (`DISK_RESERVE`, 10% of the volume) refuses uploads with `507` before SQLite is ever at risk; `GET /v1/admin/storage` shows who holds the bytes; `agenttransfer doctor` reports the guard's state.
- The public identity-free pages (`/f/`, `/u/`, index) are per-IP rate-limited (IPv6 by /64 — full addresses would be 2^64 free identities) with an automatic 15-minute ban for hammering; uploads carry a slow-body read deadline (`UPLOAD_BODY_TIMEOUT`) while downloads deliberately stream untimed.
- Agents can be deleted (`DELETE /v1/agents/self`, or by the admin) — everything they own is removed and their links severed, but their **receipts stay**: the chain is append-only evidence.
- Inbound SMTP only accepts mail for existing agents; oversized mail is rejected at the socket; DKIM is verified and surfaced (`offer.trusted` requires a pass aligned with the From domain).
- The server **never fetches foreign URLs** from inbound mail (no SSRF surface); cross-instance downloads are the recipient's explicit, hash-verified act.
- Connect instances are anonymous but fenced: outbound email needs a verified owner, every instance has daily send/egress caps and a suspend switch, and queued mail is parsed (and DKIM-checked) by *your* machine, not the host. See [docs/connect.md](docs/connect.md).
- Not yet: encryption at rest (use disk encryption), virus scanning (hook ClamAV in front of `/v1/files` if you need it), SPF checking (DKIM is enforced instead). See [SECURITY.md](SECURITY.md).

## Docs

- [docs/connect.md](docs/connect.md) — go live from any machine; run your own connect host; abuse safeguards
- [docs/self-hosting.md](docs/self-hosting.md) — VPS setup, DNS, Docker, systemd, backups
- [docs/api.md](docs/api.md) — full REST reference
- [docs/protocol.md](docs/protocol.md) — manifest format, receipt spec, `/.well-known/agenttransfer`

## Development

```sh
make test      # unit + end-to-end tests
make demo      # build and run the demo
make lint      # gofmt + go vet
```

Pure Go (1.25+), no cgo (`modernc.org/sqlite`), cross-compiles to a single static binary. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status & roadmap

Early but complete: files, links, burn-after-read, send/inbox with threading and idempotency, inbound SMTP + aligned DKIM, MCP, signed receipts, Connect (tunnel + store-and-forward email + quotas), demo, doctor. **agenttransfer.dev is live with open signup** — the instructions at the top of this page work today. Connect *hosting* there (public subdomains for `serve --connect`) is next; until it ships, `--connect` needs a host you run.

Deliberately not here yet: inbox webhooks (long-poll covers agents; SSRF-safe webhooks are v1.1), auto-fetching foreign offers (same reason), S3 blob backend, resumable uploads, IMAP (never — humans already have inboxes).

## License

[MIT](LICENSE)
