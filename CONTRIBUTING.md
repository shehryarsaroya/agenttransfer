# Contributing to AgentTransfer

Thanks for helping build file transfer for AI agents.

## Ground rules

- **One binary, no cgo, minimal deps.** The whole pitch is `scp` a static binary to a $5 VPS. New dependencies need a strong reason; platform lock-in (managed queues, proprietary APIs) is out.
- **Email is the control plane, HTTPS is the data plane.** Bytes never ride through email or MCP tool calls; identity and notification never require a custom registry.
- **The canonical receipt encoding is frozen.** Anything that changes `Receipt.Canonical()` output breaks every existing chain. Don't.
- **Public surface stays ephemeral.** Share links and unclaimed arrivals expire; features that make unauthenticated data live forever will be declined.
- **No server-side fetching of URLs from inbound mail** (SSRF). Recipients download explicitly. The same rule governs webhook delivery: the target IP is validated at connect time, and only public unicast is reachable.
- **Encryption is client-side; the server never sees plaintext or keys.** `--encrypt`/`--seal` encrypt before upload and the server stores ciphertext only. Don't add a code path that decrypts server-side or accepts a key over the wire.

## Dev loop

```sh
make test    # unit + end-to-end (httptest) suite
make demo    # the 30-second story; also CI's smoke test
make lint    # gofmt + go vet — CI enforces both
```

Layout:

```
main.go                 # subcommand dispatch
internal/server/        # HTTP API, MCP-over-HTTP, share pages, inbound SMTP, janitor, config
internal/server/api.go        # agents, folder, links, send, inbox, discovery, policy handlers
internal/server/spaces.go     # spaces HTTP handlers (see docs/spaces.md)
internal/server/webhooks.go   # SSRF-safe webhook delivery worker + signing (see docs/webhooks.md)
internal/server/connect_*.go  # Connect: tunnel host + client (see docs/connect.md)
internal/store/         # SQLite + sha256-addressed blob store + receipt chain writer
internal/store/cards.go       # opt-in discovery cards + directory (see docs/discovery.md)
internal/store/spaces.go      # spaces: membership + shared event-stream tables (see docs/spaces.md)
internal/store/policy.go      # recipient accept policy + quarantine (see docs/identity-and-trust.md)
internal/store/webhooks.go    # webhook + delivery-queue tables and queries
internal/receipt/       # canonical encoding, signing, chain verification
internal/mail/          # outbound MIME build + relay submission, inbound parsing
internal/proto/         # the A2A-aligned manifest types
internal/seal/          # age wrappers: symmetric + sealed (X25519) streaming encryption
internal/cli/           # client commands, demo, doctor
internal/cli/mcp.go     # the local `agenttransfer mcp` stdio bridge (see docs/mcp.md)
internal/cli/spaces.go  # the space-* CLI commands
internal/cli/crypto.go  # client-side --encrypt / --seal, identity keypair, verify-on-download
```

### Storage: migrations and blob GC

- **Schema changes go through the migration framework.** `internal/store/store.go` holds an ordered `migrations` slice; each entry runs once, in order, inside a transaction, and `PRAGMA user_version` records how many have applied. Append a new migration — **never edit a shipped one**, or existing databases skip it. Index `i` is version `i+1` (v1 base + connect + webhooks, v2 cards, v3 spaces, v4 policy).
- **Blobs are not reference-counted.** There is no refcount column to keep consistent. `DeleteOrphanBlobs` computes reference-ness on demand (any file or active link pointing at the sha256) and runs in the janitor, with a grace period so a freshly written blob isn't reaped before its first reference lands. A committed row always protects its blob.
- **Agent-scoped tables carry `ON DELETE CASCADE`.** Deleting an agent removes just the parent row; SQLite reaps its files, links, messages, memberships, cards, and the rest. Keep new agent-scoped tables consistent with this (and let the orphan-blob GC reclaim the bytes).

## Pull requests

- Include a test that fails without your change (the e2e suite in `internal/server/e2e_test.go` makes most behaviors easy to pin).
- `agenttransfer demo` must still pass — it's the contract with every README reader.
- Update `docs/` when you change API surface, config, or the protocol; `docs/protocol.md` is normative for interop.
- Keep error messages actionable — operators read them at 2 a.m.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please don't open public issues for vulnerabilities.
