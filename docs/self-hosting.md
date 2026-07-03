# Self-hosting AgentTransfer

Three ways to run your own instance, most-effort-last:

1. **Connect client (easiest, any machine):** `agenttransfer serve --connect` borrows a public URL + email service from a connect host over one outbound tunnel — no domain, DNS, ports, or relay. See [connect.md](connect.md).
2. **Classic VPS (this page):** everything is yours — your domain, your ports, your relay. No third party in the loop, hosted or otherwise.
3. **Your own connect host (this page + one section of [connect.md](connect.md)):** a classic VPS instance that *also* hands out subdomains to your other machines.

The rest of this page is path 2 — the fully self-reliant setup. A complete instance is: one binary, one data directory, three DNS records, and one outbound relay key. A $5 VPS is plenty — the binary is static, SQLite is embedded, and blobs are files on disk.

Everything you need, up front:

- **A Linux VPS** with a static IPv4 and inbound ports **25, 80, 443** open (~$5/mo; port 25 is the selective one — see the provider notes below)
- **A domain** (or subdomain) you control, e.g. `agents.example.com`
- **An outbound relay key** — Resend's free tier works, or any SMTP submission endpoint
- **Go 1.25+ to build, or Docker** (`Dockerfile` + `compose.yaml` ship in the repo)

Nothing else: no database server, no S3, no reverse proxy, no message queue. All state lives in one folder.

## 1. Pick a box

Any Linux VPS with a static IPv4 and **inbound ports 25, 80, 443** open works. Notes by provider:

- **Hetzner / Contabo / Netcup**: inbound 25 is open (some providers gate *outbound* 25 — irrelevant here, outbound goes through your relay on 587).
- **AWS / GCP / Oracle / Vultr**: check inbound 25; some block or filter SMTP entirely. If port 25 is sealed, you can still run everything except *receiving* email from other instances/humans (sending still works via the relay).
- Local/dev: skip all of this — `agenttransfer serve` with no config runs a full local instance.

Verify from your laptop after setup: `nc -vz agents.example.com 25`.

## 2. DNS (three records + relay records)

For `agents.example.com` on IP `203.0.113.7`:

| Type | Name | Value |
|---|---|---|
| `A` | `agents.example.com` | `203.0.113.7` |
| `MX` | `agents.example.com` | `agents.example.com` (priority 10) |
| `TXT` | `agents.example.com` | `v=spf1 ~all` *(plus whatever your relay tells you)* |

Your **outbound relay** (next step) will give you 2–3 more records (DKIM/SPF/return-path) during domain verification — paste those too. That's what makes agent email land in inboxes instead of spam.

Also add a DMARC record so nobody can spoof your domain (spoofed mail tanks your sender reputation): `TXT _dmarc.agents.example.com` → `v=DMARC1; p=reject; rua=mailto:you@example.com`.

If your DNS is on Cloudflare: every record must be **DNS-only (grey cloud), not proxied** — the proxy can't carry port 25 and breaks the Connect tunnel upgrade.

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

### Behind a reverse proxy

Terminate TLS at your proxy, forward to `:8080`, and run with:

```sh
BEHIND_PROXY=true HTTP_ADDR=:8080 PUBLIC_URL=https://agents.example.com DOMAIN=agents.example.com agenttransfer serve
```

Port 25 must still reach the binary directly (SMTP doesn't proxy through nginx).

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

Hand the returned `api_key` to your agent (MCP or REST — see the [README](../README.md)). For a public instance, set `OPEN_SIGNUP=true`: signups get per-IP rate limits, at most `MAX_AGENTS_PER_OWNER` agents per owner email, a reduced storage quota (`STORAGE_QUOTA_UNVERIFIED`, 400MB) whose files expire within `UNVERIFIED_FILE_TTL` (24h), and must confirm their owner email (an emailed link → a Confirm button; the link itself is side-effect-free so mail scanners can't approve it). Verification unlocks outbound email, the full quota, and persistent files. Even then, each agent can only email a small circle of unique outside recipients (`HUMAN_RECIPIENTS_MAX`, default 3; the owner is exempt) — widen it per agent with `POST /v1/agents/{id}/limits`, or raise the instance default.

## Optional: also be a connect host

Add `CONNECT_DOMAIN=agents.example.com` plus wildcard DNS (`A *.agents.example.com → your IP`, `MX *.agents.example.com → agents.example.com`) and this same instance hands out public subdomains + email to your laptops and homelab machines: they run `agenttransfer serve --connect https://agents.example.com`. Per-instance quotas and the suspend switch are described in [connect.md](connect.md).

## Backups

Everything lives in `DATA_DIR`:

```
data/
  agenttransfer.db      # SQLite (WAL mode): agents, messages, links, receipts
  blobs/              # sha256-addressed file contents
```

`rsync` of the directory is a valid backup (SQLite WAL tolerates it; for strictness, `sqlite3 agenttransfer.db ".backup ..."` first, or use litestream). The `sign_seed` inside the DB is your receipt-signing identity — losing it breaks verification of future receipts, so back it up like a private key. Restore = put the directory back, start the binary.

The repo ships a nightly-snapshot unit (consistent `.backup` of the DB + tar of blobs and certs, 7-day rotation, requires `sqlite3`):

```sh
apt install -y sqlite3
cp deploy/agenttransfer-backup.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now agenttransfer-backup.timer
systemctl start agenttransfer-backup.service   # run one immediately to test
```

Snapshots land in `/var/backups/agenttransfer/`. **Pull them off the box** — a backup that dies with the disk isn't one. Simplest: a daily `rsync` from any machine you already own (`rsync -a root@host:/var/backups/agenttransfer/ ~/Backups/agenttransfer/`); sturdier: `rclone`/`restic` to any S3-compatible bucket (Cloudflare R2's free tier works).

## Upgrades

Replace the binary, restart. The schema migrates on boot (`CREATE TABLE IF NOT EXISTS` — additive). Downgrades are not supported; snapshot `DATA_DIR` before major upgrades.

## Capacity notes

- CPU: negligible (hashing dominates; ~1 GB/s/core).
- RAM: <100 MB steady; uploads/downloads stream with constant memory.
- Disk: folders are quota-bound per agent (`STORAGE_QUOTA`, default 20 GB — or `STORAGE_QUOTA_UNVERIFIED`, 400 MB, until the owner verifies); unverified agents' files also expire within `UNVERIFIED_FILE_TTL` (24h); links add no bytes (same blob); unclaimed arrivals expire.
- **The volume can't fill**: the disk guard (`DISK_RESERVE`, default 10% of the volume) refuses uploads with 507 before free space runs out. `agenttransfer doctor` shows the guard's state; `GET /v1/admin/storage` (admin token) shows the top consumers when you need to find and delete an abuser.
- Bandwidth is the real cost driver — every share-link download is your egress. The public pages are per-IP rate-limited (`IP_RATE`), which catches lazy single-source hammering; for real floods add kernel-level limits (nftables/ufw) or an edge, which are deployment choices, not app config.
