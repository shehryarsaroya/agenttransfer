# The AgentTransfer protocol

Three small, open pieces make instances interoperable: the **email manifest**, the **receipt chain**, and **instance discovery**. Everything else is implementation.

## 1. The manifest (`application/vnd.agenttransfer+json`)

Every email an AgentTransfer agent sends carries a normal human-readable body plus one MIME part with content type `application/vnd.agenttransfer+json` (attached as `agenttransfer.json`). That part **is** the protocol:

```json
{
  "v": 1,
  "from": "openclaw-dev@agents.example.com",
  "message_id": "msg_7hk2abc",
  "in_reply_to": "msg_9dk2xyz",
  "parts": [
    { "kind": "text", "text": "training set v3 — verify before use" },
    {
      "kind": "file",
      "file": {
        "name": "weights.tar.gz",
        "mimeType": "application/gzip",
        "uri": "https://agents.example.com/f/nk3Xw9pT2mQe"
      },
      "metadata": {
        "agenttransfer.sha256": "8f2a41...64 hex...",
        "agenttransfer.size": 209715200,
        "agenttransfer.expiresAt": "2026-07-03T10:00:00Z",
        "agenttransfer.once": false
      }
    }
  ]
}
```

Design rules:

- **`parts` is intentionally easy to map to A2A** (`TextPart`, `FilePart` with a URI file): `kind`, `text`, `file.name`, `file.mimeType`, `file.uri`, `metadata`. AgentTransfer extensions live only in namespaced `metadata` keys (`agenttransfer.*`). The MIME manifest remains an AgentTransfer envelope; the service does not claim to implement A2A task/message operations or publish an A2A Agent Card.
- **Bytes never ride in the manifest.** `file.uri` points at an HTTPS share link; `agenttransfer.sha256` lets any receiver verify what it fetched. Links expire (`agenttransfer.expiresAt`, ≤ 24h on default configs) — fetch promptly or ask again.
- **Encryption is optional and client-side.** When a file is encrypted (see [encryption.md](encryption.md)), the linked bytes are [age](https://age-encryption.org) ciphertext, `agenttransfer.sha256` is the hash of *that ciphertext*, and one extra key marks it: `"agenttransfer.encMode": "symmetric" | "sealed"`. The protocol carries only this tag — never a key. A receiver without the tag still verifies integrity via the sha256; a receiver that has the key (symmetric) or is the sealed recipient decrypts locally. Instances relaying the manifest see ciphertext and metadata only.
- **Authenticity = exact-domain DKIM.** A receiving instance records the DKIM verdict of the carrying email and marks the parsed offer `trusted` only on `pass` (or same-instance delivery). `pass` requires a valid signature whose `d=` domain exactly equals the From domain after normalization. This is deliberately stricter than DMARC relaxed parent/subdomain alignment. A valid signature from any other domain is recorded as `fail`. Consumers should not auto-fetch untrusted offers.
- **Receivers must not auto-fetch at ingest.** Fetching URLs out of inbound mail server-side is SSRF; AgentTransfer stores the reference and lets the recipient agent download explicitly.
- Versioning: `v` bumps only on breaking changes; unknown fields must be ignored.

### Threading

Messages carry ordinary RFC 5322 `Message-ID` (`<msg_...@instance>`), `In-Reply-To`, and `References`, so conversations thread in agent inboxes and human mail clients alike. The manifest duplicates the AgentTransfer-level ids (`message_id`, `in_reply_to`) for consumers that never see raw email headers.

## 2. Receipts

An instance maintains one append-only receipt chain signed with its ed25519 key.

```json
{
  "v": 1,
  "id": "rcp_ab12cd34",
  "ts": "2026-07-02T10:00:00.123456789Z",
  "instance": "agents.example.com",
  "actor": "openclaw-dev@agents.example.com",
  "action": "sent",
  "sha256": "8f2a41...",
  "size": 209715200,
  "target": "codex-bot@other.com",
  "message_id": "msg_7hk2abc",
  "prev": "1f4c...sha256 of the previous receipt...",
  "sig": "base64url ed25519 signature"
}
```

- `action` ∈ `uploaded | sent | received | downloaded | revoked | burned | expired | deleted | app_deployed | app_stopped | app_deleted`.
- `sha256` identifies the underlying blob. For `downloaded`, `size` is the response-body bytes actually written; a successful range request therefore records the transferred range/body size rather than the full blob size.
- **Canonical form**: the signature covers the JSON object *minus `sig`*, serialized with keys sorted alphabetically, no whitespace, integers in decimal, and zero-value optional fields (`sha256`, `size`, `target`, `message_id`) omitted. Strings use Go `encoding/json` escaping (including HTML-safe escaping). This exact byte string is also what `prev` hashes (sha256, lowercase hex). The frozen interoperability vector in `internal/receipt/receipt_test.go` must pass in every implementation.
- The first receipt has `prev: "genesis"`.
- **Verification proves only what it is given.** A genesis-to-head export (`GET /v1/receipts/export`, JSONL, oldest first) verifies signatures, ordering, and adjacency, exposing modifications or internal gaps. An empty full export is rejected. An agent's own slice (`GET /v1/receipts`) is signature-verifiable but not gap-checkable. Without an independently witnessed head hash/count, verification cannot detect omission of a newest suffix; an operator holding the signing seed can rewrite and re-sign history. Treat this as a tamper-evident instance audit chain, not an externally anchored transparency log.
- The signing public key is published at `/.well-known/agenttransfer` as `ed25519:<base64url raw key>`. Reference verifier: `agenttransfer verify <instance-url>` (fetches the export with `AGENTTRANSFER_ADMIN_TOKEN`) or `agenttransfer verify export.jsonl` with `AGENTTRANSFER_PUBKEY=ed25519:...` set. Exports are in chain order — verifiers must not re-sort them (timestamps are wall-clock, not monotonic).

## 3. Instance discovery — `/.well-known/agenttransfer`

```json
{
  "name": "agenttransfer",
  "version": "0.7.0",
  "instance": "agents.example.com",
  "receipt_pubkey": "ed25519:...",
  "max_file_size": 5368709120,
  "default_ttl": "3h0m0s",
  "max_ttl": "24h0m0s",
  "open_signup": false,
  "email_enabled": true,
  "protocols": { "manifest": 1, "uri_file_parts": true },
  "endpoints": { "api": "https://agents.example.com/v1", "mcp": "https://agents.example.com/mcp" },
  "app_hosting": {
    "domain": "agents.example.com",
    "url_pattern": "https://{agent-slug}.agents.example.com",
    "human_email_verification_required": true,
    "static": true,
    "containers": true,
    "storage_quota": 10737418240,
    "readiness": { "runner": true, "wildcard_dns": true }
  }
}
```

`app_hosting` is omitted when `APP_DOMAIN` is disabled. `static` is true only
after randomized wildcard-DNS probes succeed. `containers` additionally
requires a healthy runner/Docker engine and, on open-signup instances, the
operator's explicit `ALLOW_PUBLIC_CONTAINERS=true` opt-in. The `readiness`
object exposes the underlying checks; none of them weakens the per-agent
human-email gate.

Clients use it for limit discovery; verifiers use it for the public key; other instances use it to learn your endpoints. **Email is the federation** — there is no registry, no handshake, no shared infrastructure. If your agent can receive email at its address, it participates.

## Federation flow, end to end

1. Agent A (instance α) uploads; α stores the blob content-addressed.
2. A `send`s to `b@β`: α mints a fresh ≤24h link, emails β a human body + manifest, DKIM-signed via α's relay.
3. β's port-25 listener accepts (it knows agent `b`), verifies DKIM, stores the manifest as a structured offer, notifies `b`'s long-poll.
4. `b` downloads `file.uri` over HTTPS, hashes it, compares with `agenttransfer.sha256`.
5. Each instance normally appends its supported signed receipts (`sent` at α, `received`/`downloaded` at β), whose signatures can be checked against that instance's published key.

No part of this requires the two operators to know each other.
