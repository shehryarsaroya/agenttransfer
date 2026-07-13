# Security

## Reporting a vulnerability

Please email **security@agenttransfer.dev** with details and a proof of concept. Do not open a public issue. You'll get an acknowledgment within 72 hours; fixes ship before disclosure.

## Model (what protects what)

| Surface | Protection |
|---|---|
| API keys / admin token | random 256-bit, stored sha256-hashed, rotation endpoint (`rotate-key`) |
| Share links | 128-bit random tokens, server-enforced TTL ≤ `MAX_TTL`, revocation severs in-flight downloads, burn-after-read is single-flight |
| Uploads | per-file cap, per-agent storage quota (reduced tier until the owner verifies) and daily rate, streamed hashing (constant memory), slow-body read deadline (`UPLOAD_BODY_TIMEOUT` — downloads stay untimed) |
| Storage exhaustion | global free-space reserve (`DISK_RESERVE`, default 10%): API uploads and app deploys refuse with 507 while the reserve is active; unverified agents' files expire within `UNVERIFIED_FILE_TTL` (24h) until a human vouches; one owner email registers at most `MAX_AGENTS_PER_OWNER` agents; app source + expanded release + observed persistent `/data` are checked against `APP_STORAGE_QUOTA`; the janitor stops a running app that later grows over quota; `GET /v1/admin/storage` shows folder/app consumers |
| Outbound email | disabled until the agent's human owner is verified (open-signup instances) — owner CCs included; verification is a **confirm-button POST**, so scanner-prefetched links can't approve; even verified, each agent can only ever email a small circle of unique remote recipients (`HUMAN_RECIPIENTS_MAX`, owner exempt); per-agent daily send rate; relay-only (instance IP never sends); every human-bound mail carries an HMAC-signed unsubscribe link and suppressed addresses are skipped |
| Signup names | open signup can't claim reserved localparts (`postmaster`, `no-reply`, `abuse`, `self`, …); taken names get a random suffix instead of enabling squatting games |
| Inbound email | recipients must exist, size-capped at the socket, DKIM verified and surfaced — offers are `trusted` only on a pass whose signing domain aligns with the From domain; manifest URLs are stored, **never fetched server-side** (no SSRF) |
| Receipts | ed25519-signed, hash-chained, deletion-evident; public key published at `/.well-known/agenttransfer`; receipts survive agent deletion (the chain is append-only evidence) |
| Signup (open mode) | per-IP rate limit + owner email verification + per-owner agent cap |
| App eligibility | `APP_DOMAIN` must be explicitly enabled and the current owner mailbox must complete a POST-backed email challenge (`owner_verification_method=email`); operator/admin and migrated `legacy` verification have separate provenance and cannot unlock hosting |
| Static app hosts | exact one-label host routing, active-release + owner gate on every request, GET/HEAD only, immutable content-addressed blobs, traversal/link/device/duplicate/decompression limits, sha256 ETags; on-demand TLS issuance is allowed only for an active eligible app |
| App runner control | separate `agenttransfer app-runner` process; mandatory 256-bit bearer token over a local Unix socket; typed JSON operations and validated IDs/paths/images/argv; only the runner invokes Docker and the public service validates a loopback upstream before proxying |
| Dynamic app containers | source builds are serialized, time-bounded, no-cache, and use operator-selected `none`/`bridge` networking; builder CPU/memory/process flags are best-effort because support depends on the Docker backend; runtime is nonroot `65532:65532`, read-only root, all capabilities dropped, `no-new-privileges`, bounded CPU/memory/swap/PIDs and `/tmp`, only app-specific `/data` writable, image-declared volumes outside canonical `/data` and `/tmp` rejected, rotating local logs, random `127.0.0.1` published port, 2xx health gate before atomic traffic switch; every HTTP method is proxied with canonical forwarding headers |
| App lifecycle cleanup | stop removes serving but retains release/data; ordinary reset removes releases/runtimes while retaining id/slug and `/data`, explicit purge removes all four; activation and the janitor reconcile stale managed runtimes to SQLite's desired runtime; agent deletion refuses to commit if a container runner is required but unavailable, preventing orphan state; app deploy/stop/delete are signed receipts |
| Public pages (`/f/`, `/u/`, index) | per-IP rate limit (IPv6 keyed by /64 — full addresses would hand out 2^64 free identities) with an automatic 15-minute ban for repeat hammering; behind a proxy the client IP is read from the proxy-appended XFF hop, never the spoofable first entry |
| Connect instances (anonymous) | outbound email locked until a human owner verifies by magic link; per-instance daily caps on relayed sends and proxied egress; store-and-forward queue caps; suspend kill switch; random non-vanity subdomains; control channel rides the authenticated tunnel and is never publicly routable; the client re-verifies DKIM itself rather than trusting the host |
| Metrics | localhost or admin-token gated, never public by default |

## Known gaps (documented, not hidden)

- **No encryption at rest** — run on an encrypted volume if your threat model needs it. The blob directory and SQLite file are plaintext.
- **Docker is isolation, not a tenant-grade VM boundary.** Keep Docker and the host kernel patched. Runtime apps have bridge-network egress, and a malicious image still attacks the container/kernel boundary. Use separate VMs or a stronger sandbox for mutually hostile tenants.
- **Hosted app traffic is not covered by the control-plane IP limiter.** Static hosts are cheap immutable reads; container apps are arbitrary public HTTP services and must implement their own authentication/rate limits. Put a CDN or edge limiter in front when public bandwidth abuse matters.
- **App environment variables are not a secrets manager.** Values are omitted from SQLite, API responses, receipts, and normal CLI/MCP output, but they are visible to the container, Docker metadata, the in-memory deploy path, and a privileged host operator. Use scoped, rotatable credentials.
- **Docker storage is partly outside the blob quota.** Persistent `/data` is measured and enforced, but image layers/build cache are shared Docker state rather than exact per-agent charges. `DISK_RESERVE` gates API writes; it cannot prevent Docker or a running process from consuming host space between checks. Monitor the volume and Docker cache.
- **An over-quota `/data` volume has no agent shell or file browser.** The janitor stops the runtime and keeps its bytes. The agent's only self-service recovery is destructive purge; preserve/export or reduce `$APP_ROOT/data/<app-id>` as the operator when recovery matters.
- **The shipped backup briefly takes the public service offline.** It stops HTTP/SMTP for the SQLite + immutable-blob hardlink snapshot so references cannot race garbage collection, then restarts before archive compression. Containers continue running and `/data` is only a best-effort live copy—not a point-in-time snapshot. Monitor the logged pause and use application-native quiescing/dumps for consistent app data.
- **No virus scanning** — if you accept uploads from strangers, front `/u/` and `/v1/files` with scanning (e.g. ClamAV via a reverse proxy hook).
- **SPF is not checked** on inbound mail (DKIM is). Recorded as `spf: "none"`; treat unsigned mail accordingly.
- **Anyone with a link can download until it expires** — that's the design (unguessable + short-lived + revocable + receipted); don't put secrets in world-readable links without `once=1`.
- Local mode (`DOMAIN` unset) binds `:8080` without TLS — it's for localhost development, not the open internet.
