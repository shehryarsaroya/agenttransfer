# Connect: a public instance from any machine

Connect makes a full AgentTransfer instance runnable on a laptop, a desktop,
or any box behind NAT — **no domain, no DNS, no open ports, no relay account**.
A *connect host* (the hosted one at agenttransfer.dev, or one you run — see
below) lends your instance three things over a single outbound tunnel:

```
your laptop                                connect host (agenttransfer.dev)
┌─────────────────────────┐   one outbound  ┌────────────────────────────────┐
│ agenttransfer serve     │◄═══ tunnel ════►│ https://<name>.agenttransfer.dev│
│  --connect              │                 │   └─ proxies web traffic to you │
│                         │                 │ *@<name>.agenttransfer.dev      │
│ agents, folders, links, │                 │   └─ receives + queues your mail│
│ inbox, receipts — all   │                 │ outbound email relay            │
│ local, all yours        │                 │   └─ sends for verified owners  │
└─────────────────────────┘                 └────────────────────────────────┘
```

Your data never lives on the host: files, inboxes, keys, and receipts stay on
your machine. The host is plumbing — a public front door and a mailbox slot.

## Use it (client side)

```sh
./agenttransfer serve --connect            # uses https://agenttransfer.dev
./agenttransfer serve --connect https://hub.example.com   # or any connect host
```

First run registers anonymously and prints your assigned identity, e.g.
`https://quiet-moth-79.agenttransfer.dev`. The name and token persist in
`DATA_DIR`, so restarts keep the same address. From that moment:

- **Share links work worldwide** — `https://<name>.agenttransfer.dev/f/…`,
  served from your machine through the tunnel.
- **Agents can receive email immediately** — `bot@<name>.agenttransfer.dev`
  is a real address. Mail that arrives while your machine is asleep is queued
  on the host and delivered when the tunnel returns (store-and-forward).
- **Sending email is locked until a human vouches for the instance**:

```sh
curl -X POST http://localhost:8080/v1/connect/verify \
  -H "Authorization: Bearer <admin token>" -d '{"email":"you@example.com"}'
# open the link that lands in your mailbox and press Confirm — outbound email unlocks
```

Check state anytime: `GET /v1/connect` (admin token) → connected, name,
public URL. Suspending, quotas, and abuse handling are the host's side, below.

Everything else about the instance is unchanged: same API, same MCP endpoint
(`https://<name>.agenttransfer.dev/mcp`), same receipts, same admin token.
`CONNECT=https://…` in the environment is equivalent to the flag.

## What the host enforces (abuse safeguards)

Anonymous signup is the point — so the safeguards are structural, not
identity-based:

| Risk | Safeguard |
|---|---|
| Spam through the host's domain/relay | Outbound email **requires a verified owner email** (magic link); then ≤ `CONNECT_SEND_RATE`/day per instance (default 50). Verification mail itself is capped at 5/day and can only be triggered by the instance over its own tunnel. |
| Illegal/abusive content behind links | Per-instance egress cap (`CONNECT_BYTES_PER_DAY`, default 5 GB/day), instant `suspend` kill switch, random non-vanity names (no `paypal.<host>` lookalikes). |
| Registration floods | Per-IP rate limit; registrations that never connect are reaped after 24 h; instances idle 30 days are reaped with their queues. |
| Queue exhaustion | Store-and-forward mail capped per instance (100 messages / 64 MB); over-cap mail is refused at SMTP time with a retryable 452. |
| Tunnel misuse | The tunnel only carries traffic addressed to that instance's subdomain — it is not a general proxy. Control calls (relay, drain) are authenticated by the tunnel itself and unreachable from the public side. |

Suspend an instance (host operator):

```sh
curl -X POST https://hub.example.com/connect/admin/suspend \
  -H "Authorization: Bearer <host admin token>" \
  -d '{"name":"quiet-moth-79","suspended":true}'
```

## Run your own connect host

The hosted service is a default, not a dependency — any AgentTransfer server
can be a connect host for your own fleet (a team hub, a homelab box, a
company gateway). You need the same things as a normal public instance
([self-hosting guide](self-hosting.md)), plus two DNS records:

```sh
# on a VPS with ports 25/80/443 open
DOMAIN=hub.example.com CONNECT_DOMAIN=hub.example.com \
  OUTBOUND=resend:re_xxx ./agenttransfer serve
```

That same-domain form is for a host that does not use the wildcard for apps.
If `APP_DOMAIN=hub.example.com`, give Connect its own namespace instead:

```sh
DOMAIN=hub.example.com APP_DOMAIN=hub.example.com \
  CONNECT_DOMAIN=connect.hub.example.com \
  OUTBOUND=resend:re_xxx ./agenttransfer serve
```

`APP_DOMAIN` and `CONNECT_DOMAIN` may not be equal because both route wildcard
hosts. In the second layout, put the wildcard A/MX records under
`*.connect.hub.example.com`.

| DNS record | Value | Why |
|---|---|---|
| `A    hub.example.com` | your VPS IP | the host itself |
| `MX   hub.example.com` | `hub.example.com` | its own mail |
| `A    *.hub.example.com` | your VPS IP | instance subdomains |
| `MX   *.hub.example.com` | `hub.example.com` | instance mail |

TLS for subdomains is **on-demand**: a certificate is minted per active
subdomain at first request (no wildcard cert or DNS API needed). Note Let's
Encrypt caps issuance (~50 new certs/week per domain) — fine for a personal
or team host; a very large host should front with a wildcard cert instead.

Then point clients at it: `agenttransfer serve --connect https://hub.example.com`.

Host-side knobs: `CONNECT_SEND_RATE` (default 50/day/instance),
`CONNECT_BYTES_PER_DAY` (default 5GB/day/instance).

## Without any connect host (fully self-reliant)

Two first-class paths, both documented in [self-hosting.md](self-hosting.md):

- **Your own VPS** — the classic: your domain, port 25, autocert, your relay.
  Nothing about your instance touches anyone else's infrastructure.
- **Your own tunnel** — keep the instance at home and bring your own front
  door: `tailscale funnel 8080` or a named Cloudflare Tunnel, then run with
  `BEHIND_PROXY=true PUBLIC_URL=https://<your-tunnel-hostname>`. You get
  public links without Connect; email still needs a domain + relay (or skip
  email — same-instance transfer works fully without it).

## Protocol sketch (for implementers)

- `POST /connect/register` → `{name, token, public_url}`; anonymous, rate-limited.
- `GET /connect/tunnel` with `X-Connect-Token` + `Upgrade: agenttransfer-tunnel`
  → HTTP 101, then the raw connection carries a [yamux](https://github.com/hashicorp/yamux) session.
- Host→client streams: one per public HTTP request (plain HTTP/1.1 on the stream).
- Client→host streams: control calls — `POST /connect/relay` (outbound email),
  `GET /connect/drain` (long-poll queued mail), `POST /connect/ack`,
  `POST /connect/verifymail`. Authenticated by the tunnel; never public.
- Inbound mail is queued raw (RFC 5322 bytes) and parsed by the *client*,
  which runs its own DKIM verification — the host is not trusted for
  authenticity verdicts.
