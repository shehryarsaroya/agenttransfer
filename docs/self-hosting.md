# Self-hosting AgentTransfer

Three ways to run your own instance, most-effort-last:

1. **Connect client (easiest, any machine):** `agenttransfer serve --connect` borrows a public URL + email service from a connect host over one outbound tunnel — no domain, DNS, ports, or relay. See [connect.md](connect.md).
2. **Classic VPS (this page):** everything is yours — your domain, your ports, your relay. No third party in the loop, hosted or otherwise.
3. **Your own connect host (this page + one section of [connect.md](connect.md)):** a classic VPS instance that *also* hands out subdomains to your other machines.

The rest of this page is path 2 — the fully self-reliant setup. The server, CLI, MCP bridge, and optional container runner ship in one static binary; dynamic app hosting runs the runner as a **separate process** so the public service never gets Docker authority. Core state is one data directory: SQLite plus content-addressed blobs and, by default, app state. A small VPS is plenty for transfer and static sites; size a host for the containers you actually run. For the component and data-flow map, see [architecture.md](architecture.md).

Everything you need, up front:

- **A Linux VPS** with a static IPv4 and inbound ports **25, 80, 443** open (~$5/mo; port 25 is the selective one — see the provider notes below)
- **A domain** (or subdomain) you control, e.g. `agents.example.com`
- **An outbound relay key** — Resend's free tier works, or any SMTP submission endpoint
- **Go 1.25+ to build, or Docker** (`Dockerfile` + `compose.yaml` ship in the repo)
- **A local Docker daemon only for dynamic apps** — static app hosting does not need it

Nothing else: no database server, no S3, no reverse proxy, no message queue. All control-plane state lives in one folder.

## 1. Pick a box

Any Linux VPS with a static IPv4 and **inbound ports 25, 80, 443** open works. Notes by provider:

- **Hetzner / Contabo / Netcup**: inbound 25 is open (some providers gate *outbound* 25 — irrelevant here, outbound goes through your relay on 587).
- **AWS / GCP / Oracle / Vultr**: check inbound 25; some block or filter SMTP entirely. If port 25 is sealed, you can still run everything except *receiving* email from other instances/humans (sending still works via the relay).
- Local/dev: skip all of this — `agenttransfer serve` with no config runs a full local instance.

Verify from your laptop after setup: `nc -vz agents.example.com 25`.

## 2. DNS (core records, app wildcard, and relay records)

For `agents.example.com` on IP `203.0.113.7`:

| Type | Name | Value |
|---|---|---|
| `A` | `agents.example.com` | `203.0.113.7` |
| `MX` | `agents.example.com` | `agents.example.com` (priority 10) |
| `TXT` | `agents.example.com` | `v=spf1 ~all` *(plus whatever your relay tells you)* |
| `A` | `*.agents.example.com` | `203.0.113.7` *(when `APP_DOMAIN=agents.example.com`)* |

Your **outbound relay** (next step) will give you 2–3 more records (DKIM/SPF/return-path) during domain verification — paste those too. That's what makes agent email land in inboxes instead of spam.

Also add a DMARC record so nobody can spoof your domain (spoofed mail tanks your sender reputation): `TXT _dmarc.agents.example.com` → `v=DMARC1; p=reject; rua=mailto:you@example.com`.

The wildcard record routes agent apps to the same HTTP server. Built-in TLS issues
an individual certificate on first use only for an active, human-verified app;
unknown names cannot consume ACME issuance. If a reverse proxy terminates TLS,
it must have a wildcard certificate or equivalent per-host automation.

If your DNS is on Cloudflare: the SMTP and Connect records must be **DNS-only
(grey cloud), not proxied** — the proxy cannot carry port 25 and breaks the
Connect tunnel upgrade. A deliberately configured HTTP proxy can front app
hosts, but then use `BEHIND_PROXY=true` and let that proxy own app TLS.

## 3. Outbound relay

Outbound email never leaves your VPS's IP — deliverability is the relay's job:

- **Resend** (simplest, free tier): create an API key, verify your domain, set `OUTBOUND=resend:re_...`
- **Anything with SMTP submission**: `OUTBOUND=smtp://user:pass@smtp.provider.com:587` (or `smtps://...:465`)

## 4. Run it

### Bare binary + systemd

```sh
# build (or download a release binary)
git clone https://github.com/shehryarsaroya/agenttransfer && cd agenttransfer
go build -o /usr/local/bin/agenttransfer .

# install the unit (it uses DynamicUser + StateDirectory, so the data dir
# under /var/lib/agenttransfer is created and owned automatically)
cp deploy/agenttransfer.service /etc/systemd/system/
mkdir -p /etc/agenttransfer

cat > /etc/agenttransfer/env <<'EOF'
DOMAIN=agents.example.com
APP_DOMAIN=agents.example.com
DATA_DIR=/var/lib/agenttransfer
OUTBOUND=resend:re_xxxxxxxx
ACME_EMAIL=you@example.com
EOF
chmod 600 /etc/agenttransfer/env

systemctl enable --now agenttransfer
journalctl -u agenttransfer -f    # first boot prints your admin token ONCE
```

The binary binds :443, :80 (ACME + redirect), and :25. Either run it as root, or grant the capability to bind low ports:

```sh
setcap 'cap_net_bind_service=+ep' /usr/local/bin/agenttransfer
```

(The shipped systemd unit uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` and a dedicated user, so it works unprivileged.)

### Docker

```sh
docker compose up -d       # uses ./compose.yaml; data persists in the agenttransfer-data volume
docker compose logs agenttransfer | head -30   # grab the first-boot admin token
```

Set `APP_DOMAIN` in `compose.yaml` and add wildcard DNS for static sites. The
shipped Compose service is intentionally static-only: it does not mount the
Docker socket or include a Docker CLI. Do not "fix" that by mounting
`/var/run/docker.sock` into the public `agenttransfer` service. For container
apps, use the systemd runner setup below, or build an equivalent second runner
service that alone has the Docker CLI/socket and shares only `APP_ROOT`, the
runner Unix-socket directory, and its bearer token with the public service.

### Behind a reverse proxy

Terminate TLS at your proxy, forward to `:8080`, and run with:

```sh
BEHIND_PROXY=true HTTP_ADDR=:8080 \
  PUBLIC_URL=https://agents.example.com \
  DOMAIN=agents.example.com APP_DOMAIN=agents.example.com \
  agenttransfer serve
```

Port 25 must still reach the binary directly (SMTP doesn't proxy through nginx).
When apps are enabled, route `*.agents.example.com` to the same HTTP listener;
the proxy, not AgentTransfer, must provision those certificates.

## App hosting

Static hosting needs only two changes: set `APP_DOMAIN` on the public service
and add the wildcard A/AAAA record. The app domain may equal `DOMAIN`, giving
`alice@agents.example.com` → `https://alice.agents.example.com`. It must not
equal `CONNECT_DOMAIN`, because the app router and Connect would both own the
same wildcard namespace; use something like
`CONNECT_DOMAIN=connect.agents.example.com` instead.

Only an agent that completed the human email challenge may host. The admin
verify endpoint is intentionally insufficient. This keeps the gate meaningful
even on a personal instance while leaving keyed agents free to use all
same-instance transfer and coordination features.

### Dynamic apps: install the separate runner

Container apps require Docker and the included runner unit. The runner and
public service use the same binary, `APP_ROOT`, Unix-socket path, and random
token. Only the runner gets Docker access.

```sh
apt install -y docker.io docker-buildx openssl
systemctl enable --now docker
docker buildx version

cp deploy/agenttransfer-app-runner.service /etc/systemd/system/
cp deploy/agenttransfer-docker-prune.{service,timer} /etc/systemd/system/

# Add these to the existing /etc/agenttransfer/env. Generate this value once;
# the public service and runner must read the identical token.
APP_RUNNER_TOKEN=$(openssl rand -hex 32)
cat >> /etc/agenttransfer/env <<EOF
APP_ROOT=/var/lib/agenttransfer/apps
APP_RUNNER_SOCKET=/run/agenttransfer-app-runner/runner.sock
APP_RUNNER_TOKEN=$APP_RUNNER_TOKEN
# Runner-only policy overrides belong in this file too, for example:
# APP_BUILD_NETWORK=bridge
# APP_CPU=4
# APP_MEMORY=8GB
EOF

# The shipped runner unit reads a narrower file. Use the same generated value;
# do not copy the server's relay/admin secrets into the runner environment.
cat > /etc/agenttransfer/apps.env <<EOF
APP_ROOT=/var/lib/agenttransfer/apps
APP_RUNNER_SOCKET=/run/agenttransfer-app-runner/runner.sock
APP_RUNNER_TOKEN=$APP_RUNNER_TOKEN
EOF
chmod 600 /etc/agenttransfer/env /etc/agenttransfer/apps.env

systemctl daemon-reload
systemctl restart agenttransfer
systemctl enable --now agenttransfer-app-runner
systemctl is-active agenttransfer agenttransfer-app-runner
journalctl -u agenttransfer-app-runner -f
```

The shipped public-service unit uses a changing `DynamicUser` identity. The
runner unit therefore makes its Unix socket connectable with mode `0666`, but
every request still needs the 256-bit token and apps never receive that socket.
On a fixed-user deployment, prefer `0660` and a shared group. Never expose this
protocol over TCP, and never mount the Docker socket into the public service or
an app container.

Both `APP_RUNNER_SOCKET` and `APP_RUNNER_TOKEN` must be set on the public
service, or neither. Omitting both leaves a fully functional static-only host;
container deploys then fail cleanly without changing a live static release.
Put `APP_BUILD_NETWORK`, `APP_CPU`, `APP_MEMORY`, and the other runner settings
listed below in `apps.env`; adding them only to the public service's `env` file
does not change Docker policy and intentionally does not expose relay/admin
secrets to the runner.
If you move `APP_ROOT` away from `/var/lib/agenttransfer/apps`, also edit the
runner unit's first `ReadWritePaths=` entry to the resolved host path; systemd
does not expand environment variables in that sandbox directive.

The copied Docker-prune timer is optional. Managed-image pruning is scoped to
AgentTransfer, but Docker cannot reliably attribute builder cache to one
product, so its builder prune is host-wide. Enable it with `systemctl enable
--now agenttransfer-docker-prune.timer` only on a dedicated Docker host—or when
that seven-day cache policy is acceptable for every workload on the daemon.

### App configuration

Public-service settings:

| Variable | Default | Meaning |
|---|---:|---|
| `APP_DOMAIN` | disabled | wildcard namespace for `https://<agent-slug>.<domain>` |
| `APP_STORAGE_QUOTA` | `10GB` | active source + expanded files + observed persistent `/data` |
| `APP_BUNDLE_SIZE` | `500MB` | maximum compressed source archive |
| `APP_ROOT` | `$DATA_DIR/apps` | shared build-context and persistent-container-data root |
| `APP_RUNNER_SOCKET` | unset | local runner Unix socket; enables container deploys with the token |
| `APP_RUNNER_TOKEN` | unset | shared random runner credential, at least 32 bytes |

Runner settings (`agenttransfer app-runner`):

| Variable | Default | Meaning |
|---|---:|---|
| `APP_DOCKER_PATH` | `docker` | Docker CLI path/name |
| `APP_RUNNER_SOCKET_MODE` | `0660` | runner socket mode (`0600`, `0660`, or explicit `0666`) |
| `APP_IMAGE_PREFIX` | `agenttransfer-app` | local repository prefix for source-built images |
| `APP_BUILD_NETWORK` | `none` | Dockerfile `RUN` network: `none` or `bridge`; use `bridge` when builds must download dependencies |
| `APP_CPU` | `2` | exact runtime CPU ceiling; best-effort source-build flag |
| `APP_MEMORY` | `2GB` | exact runtime memory+swap ceiling; best-effort source-build flag |
| `APP_PIDS_LIMIT` | `256` | exact runtime process ceiling; best-effort source-build flag |
| `APP_TMPFS_SIZE` | `256MB` | writable `/tmp` tmpfs size |
| `APP_BUILD_TIMEOUT` | `15m` | source build deadline |
| `APP_PULL_TIMEOUT` | `10m` | registry pull deadline |
| `APP_HEALTH_TIMEOUT` | `60s` | startup 2xx health-check deadline |
| `APP_MAX_LOG_LINES` | `2000` | largest log tail the runner accepts |
| `APP_CONTAINER_PORT` | `8080` | runner fallback internal port; deploy requests normally set it |

The runner creates a persistent host directory for each app and mounts it at
`/data`. Root filesystems are read-only and `/tmp` is ephemeral. `/data`
survives deploys and stops; `agenttransfer app-rm --purge-data` removes it.
Back it up with the database and blobs. See [apps.md](apps.md) for the complete
deploy and threat model.

Source builds are serialized to bound host pressure. They always pull base
images, disable Docker's build cache, and receive the configured CPU,
memory/swap, and process ceilings where the selected Docker builder supports
them; those builder flags are best-effort and backend-dependent. Serialization
and `APP_BUILD_TIMEOUT` are always enforced. `APP_BUILD_NETWORK=none` isolates Dockerfile `RUN` steps but does not
block base-image pulls; `bridge` lets those steps download dependencies.
Runtime containers always use bridge networking, and their Docker `local`
logs rotate at three 10 MB files per container in addition to the bounded
`app-logs` response.

With the default `APP_ROOT`, the shipped backup unit includes `apps/data/` but
deliberately excludes `apps/contexts/`, which is transient build material. If
`APP_ROOT` is elsewhere, extend the unit or back that path up separately. Its
`/data` tar copy is a best-effort live copy, not a point-in-time or
application-consistent backup: quiesce an app or use that app's own
dump/snapshot procedure when its data requires transactional semantics.

For DB/blob consistency, the unit briefly stops the public `agenttransfer`
service, takes the SQLite snapshot, and hardlinks the immutable blob tree on the
same volume. It then restarts HTTP/SMTP through the normal path **before**
compressing the large archive; the exit trap also restarts it if a snapshot
step fails. HTTP, static sites, the app proxy, and inbound SMTP are unavailable
only for that short snapshot window (logged by the unit), so still monitor it
as the number of blobs grows. Container processes keep running throughout and
are unreachable through AgentTransfer only during that pause. The later
app-data copy happens while the public service is back online, and containers
may keep changing `/data`, which is why that part of the archive has the weaker
guarantee above. The unit writes to a temporary
archive, verifies that tar can list it, and only then atomically replaces the
dated snapshot; a live-data tar warning cannot masquerade as a completed
backup.

On a dedicated Docker host, optionally enable
`agenttransfer-docker-prune.timer`. Managed-image pruning is label-scoped, but
Docker builder-cache pruning is host-wide because build cache has no dependable
per-app label. Do not enable that timer on a shared Docker host unless this is
also the maintenance policy you want for its other workloads.

## 5. Verify the install

```sh
DOMAIN=agents.example.com OUTBOUND=resend:re_xxx agenttransfer doctor
```

Doctor checks: data dir writable, A + MX records, SPF present, port 25 reachable and answering, TLS certificate live, relay authentication. Every failure prints a copy-paste fix. Note the port-25 probe runs from wherever you run doctor — run it from a second machine to test the real path.

## 6. Create agents

```sh
curl -X POST https://agents.example.com/v1/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name":"openclaw-dev","owner_email":"you@example.com"}'
```

Hand the returned `api_key` to your agent (MCP or REST — see the [README](../README.md)). For a public instance, set `OPEN_SIGNUP=true`: signups get per-IP rate limits, at most `MAX_AGENTS_PER_OWNER` agents per owner email, a reduced storage quota (`STORAGE_QUOTA_UNVERIFIED`, 400MB) whose files expire within `UNVERIFIED_FILE_TTL` (24h), and must confirm their owner email (an emailed link → a Confirm button; the link itself is side-effect-free so mail scanners can't approve it). Human-email verification unlocks outbound email, the full persistent folder tier, and app hosting. Even then, each agent can only email a small circle of unique outside recipients (`HUMAN_RECIPIENTS_MAX`, default 3; the owner is exempt) — widen it per agent with `POST /v1/agents/{id}/limits`, or raise the instance default.

Admin-created agents are marked operator-verified for email/storage compatibility,
but that is not proof of the human mailbox and does not unlock apps. After
creation, the agent can challenge its owner address with its own key:

```sh
curl -X POST https://agents.example.com/v1/agents/self/owner \
  -H "Authorization: Bearer at_live_..." \
  -d '{"email":"you@example.com"}'
```

The owner must press Confirm before `app-deploy` is accepted.

## Optional: also be a connect host

Use a namespace distinct from apps, for example
`CONNECT_DOMAIN=connect.agents.example.com`, plus wildcard DNS
(`A *.connect.agents.example.com → your IP`,
`MX *.connect.agents.example.com → agents.example.com`), and this same
instance hands out public subdomains + email to your laptops and homelab
machines. They run
`agenttransfer serve --connect https://agents.example.com`. `APP_DOMAIN` and
`CONNECT_DOMAIN` cannot be equal. Per-instance quotas and the suspend switch
are described in [connect.md](connect.md).

## Backups

Everything lives in `DATA_DIR`:

```
data/
  agenttransfer.db      # SQLite (WAL mode): agents, messages, links, receipts
  blobs/                # sha256-addressed folder files and app releases
  apps/
    data/               # persistent container /data, by app id
    contexts/           # transient source-build materialization
```

Do not rely on a file-by-file copy of a live SQLite database: create a
consistent database snapshot first with `sqlite3 agenttransfer.db ".backup
..."`, use litestream, or stop the service while copying. The `sign_seed`
inside the DB is your receipt-signing identity — losing it breaks verification
of future receipts, so back it up like a private key. If `APP_ROOT` points
outside `DATA_DIR`, back that path up separately. Docker images and running
containers are runtime cache, not part of this backup. After a restore,
redeploy each dynamic app from its original local source/archive or OCI image
to recreate its runtime; do not assume the old container id in SQLite can be
restarted. Static releases need no such rebuild because their referenced blobs
are in the archive.

The repo ships a nightly-snapshot unit (consistent DB + hardlinked blob
snapshot, default app data and certs, 7-day rotation, requires `sqlite3`). It
briefly pauses the public service as described above:

```sh
apt install -y sqlite3
cp deploy/agenttransfer-backup.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now agenttransfer-backup.timer
systemctl start agenttransfer-backup.service   # run one immediately to test
```

Snapshots land in `/var/backups/agenttransfer/`. **Pull them off the box** — a backup that dies with the disk isn't one. Simplest: a daily `rsync` from any machine you already own (`rsync -a root@host:/var/backups/agenttransfer/ ~/Backups/agenttransfer/`); sturdier: `rclone`/`restic` to any S3-compatible bucket (Cloudflare R2's free tier works).

## Upgrades

Snapshot `DATA_DIR` (and a custom external `APP_ROOT`), replace the binary once,
then restart every process that uses it:

```sh
systemctl restart agenttransfer
systemctl restart agenttransfer-app-runner  # when installed; restart after the public service
systemctl is-active agenttransfer agenttransfer-app-runner
```

The schema migrates on server boot through ordered `PRAGMA user_version`
migrations. Downgrades are not supported. Keep the runner and public service on
the same binary version; their local protocol is an internal boundary, not a
cross-version compatibility promise. Restart the public service first because
the shipped runner unit depends on it; restarting the runner last also verifies
the new local protocol and socket before the upgrade is considered complete.

The v0.6.0 provenance migration deliberately clears the old
`owner_verified=true` bit on historical agents that have no owner mailbox; they
return to the unverified scratch tier because there is no owner claim to
substantiate. Historical rows with a mailbox retain their legacy email/storage
tier, but must complete a fresh emailed challenge before app hosting. Review
those agents after the upgrade rather than treating this as silent hosting
authorization.

The control-plane database is authoritative for which runtime should serve an
app. After each healthy container switch, and again during the minute janitor,
the runner removes other managed containers for that app; a static deployment
removes all of its old container runtimes while preserving `/data`. This
reconciliation cleans up interruptions between activation and old-runtime
removal, but it does not recreate a missing desired runtime after restore—use
a fresh deployment for that.

## Capacity notes

- CPU: negligible for transfer/static serving (hashing dominates). Dynamic apps are capped at `APP_CPU` each, but builds and several busy apps still need aggregate host capacity.
- RAM: the server stays below roughly 100 MB at rest and streams transfer bytes with constant memory. Each dynamic app may consume up to `APP_MEMORY`; leave room for Docker, builds, SQLite, and the kernel.
- Disk: folders are quota-bound per agent (`STORAGE_QUOTA`, default 20 GB — or `STORAGE_QUOTA_UNVERIFIED`, 400 MB, until the owner verifies); unverified agents' files also expire within `UNVERIFIED_FILE_TTL` (24h); links add no bytes (same blob); unclaimed arrivals expire. Each app release must fit `APP_STORAGE_QUOTA` (10 GB), and source archives are capped by `APP_BUNDLE_SIZE` (500 MB). The active and newest previous release are retained and may deduplicate physically.
- Persistent app `/data` is measured at deploy and by the minute janitor; a running app that pushes source + release + data above `APP_STORAGE_QUOTA` is stopped with its data retained. A non-purging reset also retains it, so the agent's only self-service way out of an already-over-quota volume is destructive `app-rm --purge-data`; preserve or reduce `$APP_ROOT/data/<app-id>` as the operator when recovery matters. Container image layers and build cache remain shared Docker state rather than exact per-agent charges. Watch `docker system df` and `du -sh "$APP_ROOT"`; prune unused Docker cache deliberately and preserve `$APP_ROOT/data/`. The global disk guard protects API uploads, not every byte Docker may write between checks.
- **The transfer volume has a reserve**: `DISK_RESERVE` (default 10% of the volume) refuses API uploads with 507 before free space runs out. `agenttransfer doctor` shows the guard's state; `GET /v1/admin/storage` (admin token) shows folder and retained app consumers. It is a backstop, not a substitute for monitoring Docker and `/data` growth.
- Bandwidth is the real cost driver — every share-link download is your egress. The public pages are per-IP rate-limited (`IP_RATE`), which catches lazy single-source hammering; for real floods add kernel-level limits (nftables/ufw) or an edge, which are deployment choices, not app config.
