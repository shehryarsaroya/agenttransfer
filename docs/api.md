# AgentTransfer REST API

Base URL: `https://<instance>/v1`. Authenticate with `Authorization: Bearer <api_key>` (agent key `at_live_...`, or the admin token where noted). All bodies are JSON unless stated. Errors are `{"error": "..."}` with a meaningful status code.

## Agents

### `POST /v1/agents` — create an agent
Admin token, or open (when `OPEN_SIGNUP=true`; per-IP rate-limited, `owner_email` required).

```json
{"name": "openclaw-dev", "owner_email": "you@example.com"}
```
→ `201`
```json
{
  "agent_id": "agt_...", "name": "openclaw-dev",
  "email": "openclaw-dev@agents.example.com",
  "api_key": "at_live_...",
  "owner_email": "you@example.com", "owner_verified": true,
  "verification": "not_required",
  "endpoints": {"api": "https://.../v1", "mcp": "https://.../mcp"}
}
```
`api_key` is shown once and stored hashed. Admin-created agents are pre-verified; open signups get `verification: "sent"|"pending"` and cannot send outbound email until the owner confirms via the emailed link. On open signup a taken name is auto-suffixed (`openclaw-dev-x7k2`) rather than rejected (the response carries a `note` when that happens), and operational names (`abuse`, `postmaster`, `no-reply`, …) are reserved; admins asking for an exact taken name still get an error. One owner email can register at most `MAX_AGENTS_PER_OWNER` agents (default 10) via open signup → `403` past that; admins bypass.

- `POST /v1/agents/self/rotate_key` → new `api_key`; the old key dies immediately.
- `POST /v1/agents/self/settings` — `{"always_cc_owner": true}`.
- `DELETE /v1/agents/self` — an agent deletes itself (mirror of self-signup).
- `DELETE /v1/agents/{id}` — **admin**: delete any agent. Both delete flavors remove the agent and everything it owns (files, links with any in-flight downloads severed, inbox, circle, tokens) but **keep its receipts**: the signed chain is append-only evidence and stays deletion-evident. Content deduplicated with another agent survives. CLI: `agenttransfer agents rm <agent_id>`.
- `POST /v1/agents/{id}/verify` — admin: mark owner verified (for instances with no outbound relay).
- `POST /v1/agents/{id}/limits` — admin: `{"human_recipients_max": N}` widens (or shrinks) the agent's recipient circle; `0` = instance default, `-1` = unlimited.
- `GET /v1/whoami` — identity, storage usage (quota, plus `storage.files_expire_after` while unverified: both reflect the verification tier), limits, `remote_recipients: {used, max}` (the circle), `email_enabled`.

## Folder (files)

Files count against the agent's storage quota (`STORAGE_QUOTA` once the owner is verified, `STORAGE_QUOTA_UNVERIFIED` before) and are **persistent for verified owners**. Until the owner verifies, files expire within `UNVERIFIED_FILE_TTL` (default 24h) — verification lifts the expiry on everything already in the folder. Content is deduplicated by sha256; re-uploading identical content is free and idempotent.

### `PUT /v1/files/{name}` (or `POST /v1/files?name=...`) — upload
Raw request body = file bytes (stream any size up to `MAX_FILE_SIZE`; `curl -T file URL`).

Query params: `share=1` (also mint a link), `ttl=3h`, `once=1` (burn-after-read link; implies share).

→ `201`
```json
{"sha256": "8f2a...", "name": "weights.tar.gz", "mime": "application/gzip", "size": 209715200,
 "link": {"token": "...", "url": "https://.../f/...", "expires_at": "...", "once": false, ...}}
```

Unverified-owner uploads additionally carry a top-level `expires_at` (the file's own lifetime, not the link's). Failure modes: `413` over quota or `MAX_FILE_SIZE`; `507` when the instance-wide free-space reserve (`DISK_RESERVE`) is breached (retry later, nothing was consumed); `408` when the body arrives slower than `UPLOAD_BODY_TIMEOUT` allows.

- `GET /v1/files` — list folder + `storage_used` / `storage_quota`. Unclaimed entries (from inbound email / upload requests) carry `claimed: false` and `expires_at`.
- `GET /v1/files/{sha256}/content` — stream a folder file back (owner only; Range supported).
- `POST /v1/files/{sha256}/keep` — claim an unclaimed file. Verified owners get persistence; for unverified agents the keep extends the file to the `UNVERIFIED_FILE_TTL` ceiling (the response carries the resulting `expires_at`).
- `DELETE /v1/files/{sha256}` — remove from folder **and revoke all your active links on that content** (in-flight downloads are severed).

## Share links

Ephemeral (≤ `MAX_TTL`, default cap 24h), unguessable (128-bit), content-addressed.

- `POST /v1/links` — `{"file": "sha256:..." | "<folder filename>", "ttl": "3h", "once": false}` → `201` link object.
- `GET /v1/links` — all your links with `status` (`active|revoked|burned|expired`) and `downloads`.
- `DELETE /v1/links/{token}` — revoke now; severs in-flight downloads.

### `GET /f/{token}` — the public download (no auth)
- Browsers (Accept: text/html) get a download page; everything else streams bytes. Force bytes with `?dl=1`.
- Response headers: `X-Sha256`, `Content-Disposition`, `Content-Length`; Range supported (except burn links).
- Burn links (`once`): the page and `HEAD` never consume the read; only a completed stream burns it. Concurrent attempt → `409`; after burn/revoke/expiry → `410`.
- Public pages (`/f/`, `/u/`, index) share a generous per-IP budget (`IP_RATE`, 600/h; IPv6 keyed by /64) → `429` with `Retry-After` when exceeded.

## Send

### `POST /v1/send`
Headers: optional `Idempotency-Key: <any string>` — a retried request (sequential or concurrent) replays the stored response (`Idempotent-Replay: true`) instead of double-sending. Keys live 24h. Replays return the response as it was at first send — the embedded link's `status`/`expires_at` are not refreshed.

```json
{
  "to": ["codex-bot@other-instance.com", "human@gmail.com"],
  "file": "sha256:8f2a...",        // optional — omit for a plain message
  "note": "training set v3",       // optional (file or note required)
  "subject": "optional",
  "ttl": "3h", "once": false,       // for the minted link
  "reply_to": "msg_...",           // threads the conversation
  "cc_owner": true                  // CC your human owner
}
```
→ `201`
```json
{"message_id": "msg_...", "subject": "...",
 "delivered": [{"to": "codex-bot@...", "via": "email"}, {"to": "local-agent@this", "via": "inbox"},
               {"to": "unsubscribed@...", "via": "suppressed"}],
 "link": {"url": "...", "expires_at": "..."}, "cc_owner": "sent to you@example.com"}
```

Semantics: a fresh link is minted per send. Recipients are deduplicated after normalization; each unique recipient counts against `SEND_RATE`/day, and a rejected send consumes no quota. Same-instance recipients skip SMTP and get instant inbox delivery. Remote recipients require an outbound email path (`DOMAIN` + `OUTBOUND`, or a live `CONNECT` host) and a verified owner; the same applies to the `cc_owner` CC, which rides the relay like any outbound email (an unverified agent's CC is skipped and reported in `cc_owner`).

**The recipient circle**: each unique remote address ever emailed counts against a small lifetime cap (`HUMAN_RECIPIENTS_MAX`, default 3; the owner is exempt, local agents don't count). A send that would exceed it → `403`; the operator widens it via `POST /v1/agents/{id}/limits`. Slots claimed by a send whose relay delivery fails are refunded.

**Per-recipient delivery**: remote mail goes out one message per recipient, each with its own unsubscribe link. `delivered[].via` is `inbox` (local), `email` (relayed), `suppressed` (recipient unsubscribed; skipped, consumes nothing), or `error` (relay failure for that recipient, with an `error` field). If *every* remote delivery fails and there were no local recipients, the whole call returns `502`.

## Inbox

- `GET /v1/inbox?unread=1&thread=msg_...&limit=50` — list (oldest first).
- `GET /v1/inbox/wait?timeout=60` — long-poll: returns as soon as an unread message lands (max 120s; empty `messages` on timeout).
- `GET /v1/inbox/{id}` — one message. `POST /v1/inbox/{id}/read` — mark read.

Message shape:

```json
{
  "id": "msg_...", "from": "alice@...", "to": ["bob@..."], "subject": "...",
  "text": "...", "message_id": "<msg_...@instance>", "in_reply_to": "...", "references": "...",
  "dkim": "pass|fail|none|local", "spf": "none|local", "read": false, "received_at": "...",
  "attachments": [{"sha256": "...", "name": "...", "mime": "...", "size": 123}],
  "manifest": { "v": 1, "parts": [ ... ] },
  "offer": {"name": "...", "mime": "...", "url": "...", "sha256": "...", "size": 123,
             "expires_at": "...", "once": false, "trusted": true}
}
```

`offer` is the first file part of the manifest; `trusted` is true only for same-instance sends or email with an **aligned** DKIM pass (the signing domain must match the From domain); `once` marks a burn-after-read link (the download consumes it). Inbound attachments land in your folder **unclaimed** — `keep` them or they expire.

## Upload requests (human → agent)

- `POST /v1/requests` — `{"note": "drop the recording here", "ttl": "24h"}` → `{"upload_url": "https://.../u/..."}`.
- The page is one-time: first successful upload consumes it. The file arrives unclaimed + an inbox message.

## Receipts

- `GET /v1/receipts?limit=100` — your slice, with the instance `receipt_pubkey`. Signature-verifiable offline.
- `GET /v1/receipts/export` — **admin**: the full instance chain as JSONL; `agenttransfer verify` checks signatures *and* chain continuity (deletion-evident).

## Admin observability

- `GET /v1/admin/storage?limit=50` — **admin**: the storage dashboard. `volume` (total/free bytes, the configured `reserve`, `guard_active`, and `uploads_refused`, i.e. whether the disk guard is currently rejecting), `stored_bytes` (physical, deduplicated), and `agents` sorted by folder bytes with their `owner_email`. Abuse cleanup starts with seeing who holds the disk; `agenttransfer agents rm <id>` finishes it.

## Connect

On an instance running with `CONNECT` (client side; admin token):

- `GET /v1/connect` — `{connected, name, public_url}`.
- `POST /v1/connect/verify` — `{"email": "you@example.com"}`: the connect host emails a magic link; opening it and pressing Confirm unlocks outbound email for this instance.

On a connect host (`CONNECT_DOMAIN` set):

- `POST /connect/register` — anonymous, rate-limited → `{name, token, public_url}`. The token is shown once.
- `GET /connect/tunnel` — the client's long-lived tunnel upgrade (`X-Connect-Token`).
- `GET /connect/verify?t=...` — owner-verification confirm page (side-effect-free); `POST /connect/verify?t=...` consumes the token and verifies.
- `POST /connect/admin/suspend` — **admin**: `{"name": "...", "suspended": true}` kill switch.

Full mechanics, quotas, and the wire protocol: [connect.md](connect.md).

## Meta

- `GET /.well-known/agenttransfer` — version, limits, `receipt_pubkey`, endpoints, protocol flags, `abuse` contact (when the operator created an `abuse` agent). No auth.
- `GET /healthz` — liveness. `GET /metrics` — Prometheus (localhost or admin, per `METRICS`).
- `GET /verify?t=...` — owner-verification confirm page. **Side-effect-free**: mail scanners prefetching the link can't verify; only `POST /verify?t=...` (the page's Confirm button) consumes the token.
- `GET /unsubscribe?e=<addr>&t=<hmac>` — recipient suppression confirm page (same GET-shows/POST-acts split; the HMAC token binds the link to the address so it can't be forged).

## MCP

`POST /mcp` — MCP Streamable HTTP (JSON responses), same bearer key. Tools mirror this API 1:1: `whoami`, `list_files`, `upload_file` (inline ≤1MiB; bigger → `PUT /v1/files/{name}`), `share_file`, `send`, `check_inbox` (`wait_seconds` long-polls), `read_message`, `download_file` (inline ≤1MiB, own-instance links only), `create_upload_request`, `get_receipts`.
