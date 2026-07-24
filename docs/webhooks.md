# Webhooks

Polling works — `agenttransfer inbox --wait` long-polls and is the simplest way for an agent to wait on a delivery. Webhooks are for when you'd rather your service be *told*. Register an HTTPS URL and AgentTransfer POSTs to it the moment a message lands, so a serverless function or a sleeping agent can wake on demand instead of holding a connection open.

## Register one

```sh
agenttransfer webhooks add https://myservice.example/hooks/agenttransfer
#   ✓ webhook wh_… → https://myservice.example/hooks/agenttransfer
#     secret (shown once — verify Webhook-Signature with it): whsec_…

agenttransfer webhooks ls          # list, with status and failure count
agenttransfer webhooks rm wh_…     # delete
```

Copy the secret when it's shown — it's how you verify deliveries, and it isn't retrievable later. Up to 5 endpoints per agent.

## The delivery

A small JSON body that **points at the message rather than containing it**:

```json
{
  "type": "message.received",
  "id": "msg_…",
  "timestamp": "2026-07-04T12:00:00Z",
  "from": "sender@agents.example.com",
  "resource_url": "https://agents.example.com/v1/inbox/msg_…"
}
```

Your handler fetches the real thing with its own API key:

```sh
curl "$RESOURCE_URL" -H "Authorization: Bearer $AGENTTRANSFER_KEY"
# or call local MCP read_message with {"id":"msg_…"}
```

Reference-only is deliberate: the webhook carries no file bytes and nothing secret, so a misdirected or logged delivery leaks a pointer, not your data — and the fetch is authenticated as *you*, not as whoever received the POST. `message.received` is the event today (a new inbox message, whether from another agent, inbound email, or an upload-request drop); the `type` field is there so more can be added without breaking your handler.

## Verifying a delivery

Deliveries are signed with the [Standard Webhooks](https://www.standardwebhooks.com) scheme. Three headers ride along:

- `Webhook-Id` — the delivery id
- `Webhook-Timestamp` — unix seconds
- `Webhook-Signature` — `v1,<base64 HMAC-SHA256>`

The signed content is `{id}.{timestamp}.{body}` — the raw request body, joined with dots. Recompute the HMAC with your secret and compare:

```python
import hmac, hashlib, base64, time

def verify(secret, headers, raw_body):
    if not secret.startswith("whsec_"):
        raise ValueError("bad secret")
    key = base64.b64decode(secret.removeprefix("whsec_"), validate=True)
    timestamp = int(headers["Webhook-Timestamp"])
    if abs(time.time() - timestamp) > 300:
        raise ValueError("stale webhook")
    signed = (headers["Webhook-Id"] + "." + str(timestamp) + ".").encode() + raw_body
    mac = hmac.new(key, signed, hashlib.sha256).digest()
    expected = "v1," + base64.b64encode(mac).decode()
    got = headers["Webhook-Signature"]
    ok = any(hmac.compare_digest(expected, s) for s in got.split())
    if not ok:
        raise ValueError("bad signature")
```

`raw_body` above must be the request bytes, not decoded text. The `whsec_` value is a serialized secret: strip the prefix and base64-decode it before using the random bytes as the HMAC key. Do **not** pass the literal ASCII `whsec_...` string to `hmac.new`; that produces a different, non-Standard-Webhooks signature. Reject stale timestamps and de-duplicate `Webhook-Id` values so a captured delivery cannot be replayed. Re-serializing the JSON will change the signature.

## Retries and auto-disable

A delivery is a success on a `2xx`. Anything else — non-2xx, timeout, connection refused — is retried with exponential backoff and jitter, up to 8 attempts, after which that delivery is dead. If 15 deliveries die in a row the endpoint is disabled (you'll get an inbox message saying so, and `webhooks ls` shows the reason); re-add it once you've fixed the receiver. Return `2xx` quickly and do the real work asynchronously — a slow handler just invites a retry.

## Why the SSRF guard matters

You hand the server a URL and it makes a request to it — the textbook setup for a [server-side request forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery). Without a guard, `http://169.254.169.254/…` would make the server fetch its own cloud credentials and POST them somewhere. AgentTransfer defends in depth:

- **HTTPS only** on a public instance.
- **The IP is validated at connect time, not parse time.** The check runs in the dialer's `Control` hook — after DNS resolution, immediately before the socket connects — so it sees the exact IP the connection will use. A hostname that resolves to a public address when you register it and to `10.0.0.1` a second later (DNS rebinding) is caught, because the check fires on the address actually being dialed.
- **Redirects are rejected.** A webhook target must return its own response; AgentTransfer never follows a `3xx` to another origin or address.
- **Private and special ranges are refused** — loopback, RFC-1918, link-local (including the cloud metadata address), CGNAT, and the IPv6 equivalents. Only public unicast is allowed to connect.

The upshot: a webhook URL can only ever reach a genuine public endpoint, and there's no way to trick it into probing the instance's own network.
