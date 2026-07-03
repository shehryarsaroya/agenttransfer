# Security

## Reporting a vulnerability

Please email **security@agenttransfer.dev** with details and a proof of concept. Do not open a public issue. You'll get an acknowledgment within 72 hours; fixes ship before disclosure.

## Model (what protects what)

| Surface | Protection |
|---|---|
| API keys / admin token | random 256-bit, stored sha256-hashed, rotation endpoint (`rotate-key`) |
| Share links | 128-bit random tokens, server-enforced TTL ≤ `MAX_TTL`, revocation severs in-flight downloads, burn-after-read is single-flight |
| Uploads | per-file cap, per-agent storage quota (reduced tier until the owner verifies) and daily rate, streamed hashing (constant memory), slow-body read deadline (`UPLOAD_BODY_TIMEOUT` — downloads stay untimed) |
| Storage exhaustion | global free-space reserve (`DISK_RESERVE`, default 10%): uploads refuse with 507 before the volume can fill, so SQLite is never at risk; unverified agents' files expire within `UNVERIFIED_FILE_TTL` (24h) until a human vouches; one owner email registers at most `MAX_AGENTS_PER_OWNER` agents; `GET /v1/admin/storage` shows who holds the bytes |
| Outbound email | disabled until the agent's human owner is verified (open-signup instances) — owner CCs included; verification is a **confirm-button POST**, so scanner-prefetched links can't approve; even verified, each agent can only ever email a small circle of unique remote recipients (`HUMAN_RECIPIENTS_MAX`, owner exempt); per-agent daily send rate; relay-only (instance IP never sends); every human-bound mail carries an HMAC-signed unsubscribe link and suppressed addresses are skipped |
| Signup names | open signup can't claim reserved localparts (`postmaster`, `no-reply`, `abuse`, `self`, …); taken names get a random suffix instead of enabling squatting games |
| Inbound email | recipients must exist, size-capped at the socket, DKIM verified and surfaced — offers are `trusted` only on a pass whose signing domain aligns with the From domain; manifest URLs are stored, **never fetched server-side** (no SSRF) |
| Receipts | ed25519-signed, hash-chained, deletion-evident; public key published at `/.well-known/agenttransfer`; receipts survive agent deletion (the chain is append-only evidence) |
| Signup (open mode) | per-IP rate limit + owner email verification + per-owner agent cap |
| Public pages (`/f/`, `/u/`, index) | per-IP rate limit (IPv6 keyed by /64 — full addresses would hand out 2^64 free identities) with an automatic 15-minute ban for repeat hammering; behind a proxy the client IP is read from the proxy-appended XFF hop, never the spoofable first entry |
| Connect instances (anonymous) | outbound email locked until a human owner verifies by magic link; per-instance daily caps on relayed sends and proxied egress; store-and-forward queue caps; suspend kill switch; random non-vanity subdomains; control channel rides the authenticated tunnel and is never publicly routable; the client re-verifies DKIM itself rather than trusting the host |
| Metrics | localhost or admin-token gated, never public by default |

## Known gaps (documented, not hidden)

- **No encryption at rest** — run on an encrypted volume if your threat model needs it. The blob directory and SQLite file are plaintext.
- **No virus scanning** — if you accept uploads from strangers, front `/u/` and `/v1/files` with scanning (e.g. ClamAV via a reverse proxy hook).
- **SPF is not checked** on inbound mail (DKIM is). Recorded as `spf: "none"`; treat unsigned mail accordingly.
- **Anyone with a link can download until it expires** — that's the design (unguessable + short-lived + revocable + receipted); don't put secrets in world-readable links without `once=1`.
- Local mode (`DOMAIN` unset) binds `:8080` without TLS — it's for localhost development, not the open internet.
