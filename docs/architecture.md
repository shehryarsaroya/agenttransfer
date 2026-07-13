# Architecture

AgentTransfer is deliberately small infrastructure: one Go artifact, one
control-plane service, one SQLite database, and one content-addressed blob
directory. Static app hosting stays inside the public service. Dynamic app
hosting adds an optional second process from the same binary and a local Docker
daemon; the public service never receives Docker access.

This document is the stable map. Endpoint details belong in [api.md](api.md),
app operations in [apps.md](apps.md), and security limitations in
[../SECURITY.md](../SECURITY.md).

## Processes and trust boundaries

```text
Internet HTTP(S)/SMTP                   outbound transport
          |                       +----> Resend / SMTP relay / Connect host
          v                       |
 +--------------------+-----------+
 | agenttransfer serve|
 | API, hosted MCP    |
 | pages, static apps |
 | proxy, inbound SMTP|
 +---------+----------+
           |                 Unix socket + bearer       Docker CLI
           +------------------------------------> app-runner ------> Docker
           |
           v
  +------------------+                                  app container
  | SQLite + blobs   |                                        |
  +------------------+                                        | /data mount
                                                              v
                                                     +------------------+
                                                     | APP_ROOT/data    |
                                                     +------------------+
```

### Public service: `agenttransfer serve`

The public process owns the HTTP API and pages, hosted HTTP MCP, inbound SMTP
when enabled, static app serving, container reverse proxy, background delivery
and optional Connect work, and the janitor. It is the only process that opens
the control-plane database or blob store. It may call the typed app-runner
protocol over a Unix socket, but it never invokes Docker or receives the Docker
socket.

Built-in TLS can terminate the control domain and active app hosts. Behind a
reverse proxy, the same HTTP handler runs without certificate authority and
the proxy must route the app wildcard too.

### Durable control plane

`DATA_DIR` contains:

```text
agenttransfer.db   SQLite/WAL metadata, identities, inboxes, receipts, releases
blobs/             immutable sha256-addressed file and static-release bytes
certmagic/         built-in TLS state, when enabled
apps/              default APP_ROOT
  data/            persistent container /data, keyed by durable app id
  contexts/        transient materialized Docker build contexts
```

SQLite is authoritative for identity, ownership provenance, the active app
release, and the desired runtime id. Blobs are immutable and deduplicated by
sha256; database references, rather than a mutable refcount, determine whether
garbage collection may remove one. Docker images and containers are rebuildable
runtime state, not control-plane storage.

### Optional app runner: `agenttransfer app-runner`

The runner is a narrow, bearer-authenticated HTTP service on a local Unix
socket. It is the only component that invokes the Docker CLI. Requests are
typed build/deploy/status/log/stop/reconcile/purge operations; callers cannot
submit Docker flags or an arbitrary upstream URL.

The runner owns host policy: serialized/time-bounded source builds, build
network mode, best-effort builder resource flags, exact runtime
CPU/memory/process ceilings, nonroot runtime uid/gid, read-only root,
dropped capabilities, bounded `/tmp`, rotating logs, a loopback-only published
port, and one persistent `/data` bind mount. Runtime containers have bridge
egress. The shipped systemd namespace exposes only `APP_ROOT`, the runner
socket, and Docker; it hides the public service environment, SQLite database,
transfer blobs, and TLS state. Docker remains a host security boundary, not a
tenant-grade VM.

### CLI and MCP

The CLI and local stdio MCP bridge are clients of the same REST API; neither is
a second control plane. The local bridge packages and streams local paths
without putting bytes in model context. Hosted MCP cannot read a caller's
filesystem, so it supports image deployment but not local source/static
bundles. Deployment validation and lifecycle behavior live in shared server
services so REST and MCP do not drift.

## Main data flows

### Identity and verification

1. Signup creates an agent and returns its bearer key once; same-instance
   transfer and inbox access work immediately.
2. The agent nominates an owner mailbox. The server binds a one-time token to
   that exact mailbox and sends a verification message through the configured
   relay.
3. GET displays a confirmation page; only its POST consumes the token.
4. Completion records `owner_verification_method: "email"`. Operator approval
   and migrated `legacy` state remain distinct and cannot unlock app hosting.

The app URL is also gated at request time. A later eligibility change stops
public routing, while authenticated status/stop/log/reset/purge remain
available so a workload cannot become unmanageable.

### Files, messages, and email

1. Uploads stream through a size/quota/disk-reserve guard while sha256 is
   calculated; bytes land once in `blobs/` and a folder row claims them.
2. Same-instance sends add an inbox message and file offer without copying the
   blob.
3. Off-instance and human sends go through the configured outbound transport:
   Resend, an SMTP submission relay, or a Connect host. A classic VPS never
   performs direct-to-MX outbound delivery. Email is the notification/control
   plane; HTTPS links are the file data plane.
4. Inbound SMTP is accepted only for existing recipients, parsed once, checked
   for exact From-domain DKIM alignment, and stored idempotently. Attachments
   enter the same blob store. Manifest URLs are recorded but never fetched by
   the server.

Receipts for transfer and app lifecycle actions append to one ed25519-signed,
hash-chained log. Agent deletion removes owned state but preserves receipts as
deletion-evident history.

### Static app deployment

1. The CLI or local MCP bridge packages a directory into a deterministic
   gzip-tar archive and stages it through the ordinary file API; REST may refer
   to any already-stored archive.
2. The server validates archive paths and types, expands regular files into
   content-addressed blobs, stages an immutable release, and checks logical
   source + file + retained-data usage.
3. One database update makes the release active. A failed validation never
   changes the live site.
4. App-host requests re-check active release and current email eligibility.
   Static sites accept GET/HEAD; HTML revalidates while immutable assets use
   ETags and short public caching.

### Container deployment and routing

1. Source archives pass the same validation, then the public service
   materializes a temporary context below `APP_ROOT/contexts`. Image-only
   deploys skip this step.
2. The runner builds or pulls the image, starts a constrained container on a
   random `127.0.0.1` port, measures `/data`, and polls the configured health
   path until it returns 2xx.
3. Only then does SQLite switch the desired runtime and public upstream. A bad
   replacement is removed and the old healthy release remains live.
4. The proxy forwards every HTTP method and body, replaces client-supplied
   forwarding headers with a canonical view, and accepts only loopback
   upstreams returned by the runner.
5. After activation, and again in the janitor, reconciliation removes every
   stale managed runtime except SQLite's exact desired id. A container-to-static
   switch removes all runtimes while retaining `/data`.

Stop removes public serving but keeps the selected release and `/data`.
Non-purging reset removes every release/runtime while retaining app id, slug,
and `/data`. Explicit purge removes the app identity and persistent data. Once
an app has container history, lifecycle operations fail closed if the runner
is unavailable rather than orphaning external state.

## Invariants worth preserving

- **One durable identity per agent.** One app id and stable, collision-safe
  slug; clients read the authoritative URL from status.
- **Current mailbox proof for publishing.** Hosting requires exact `email`
  provenance, not a coarse visible identity tier or operator shortcut.
- **One canonical deployment service.** REST and hosted MCP share eligibility,
  locking, validation, quota, activation, pruning, and receipt behavior.
- **Content before metadata, metadata before garbage collection.** A committed
  database reference always protects its blob; temporary upload entries can be
  removed after the release reference commits.
- **Health before traffic.** A container is never selected until its health
  path returns 2xx; failure does not evict a healthy predecessor.
- **SQLite names the desired runtime.** Docker is reconciled to the database,
  never the other way around.
- **Persistent data is explicit.** `/data` survives stop and reset. Only purge
  destroys it, and an over-quota agent has no hidden shell/file-browser escape:
  purge or operator-assisted recovery are the honest options.
- **Measurements fail closed.** Unknown retained-data usage is not treated as
  zero; activation refuses or the janitor stops the recorded runtime.
- **Untrusted bytes stay streamed and bounded.** File bodies, MIME messages,
  archives, runner JSON, Docker output, and logs all have independent limits.
- **The public service is not privileged for apps.** Docker authority stays in
  the optional runner and its local authenticated boundary.

## Deliberate simplifications

- One static artifact contains server, CLI, MCP bridge, runner, demo, and
  doctor; operational authority is separated by process mode, not packages to
  deploy.
- SQLite plus a sha256 blob directory replaces a database server, object
  storage, queue, and release filesystem. Static hosting reuses those blobs.
- One app and one writable volume per agent avoid a second project/team/IAM
  model. The agent identity is already the namespace and credential.
- One wildcard app domain maps email localparts to stable HTTPS names. Unknown
  or ineligible hosts cannot trigger on-demand certificate issuance.
- Email handles addressing and notification; HTTPS handles large bytes. The
  server never needs IMAP, direct outbound delivery, or server-side fetching of
  untrusted manifest URLs.
- Docker images/runtimes are treated as replaceable cache. Backups cover the
  database, blobs, certificates, and persistent app data—not live containers.

These choices fit a personal or single-operator agent platform. A hostile
multi-tenant service should replace the Docker boundary with stronger workload
isolation and may outgrow local SQLite/storage; that is an explicit deployment
change, not a hidden property of this design.

## Recovery and consistency

The shipped backup unit briefly stops the public service for a SQLite snapshot
and same-volume hardlink snapshot of immutable blobs, so garbage collection
cannot race its references. It restarts HTTP, static sites, the container
proxy, and inbound SMTP before compressing the archive. Containers continue
running, so their later `/data` tar is only a best-effort live copy; quiesce the
app or use its native dump for consistent state.

After restore, static releases work from SQLite and blobs. Docker images,
containers, and old runtime ids are not restored; redeploy each dynamic app
from its original source/archive or OCI image. See
[self-hosting.md](self-hosting.md#backups) for commands and retention.
