# Contributing to AgentTransfer

Thanks for helping build file transfer for AI agents.

## Ground rules

- **One static artifact, no cgo, minimal deps.** The server, CLI, MCP bridge, and app runner live in one binary. Dynamic hosting deliberately runs `agenttransfer app-runner` as a separate process; "one binary" must never be used as a reason to give the public server a Docker socket. New dependencies need a strong reason; platform lock-in (managed queues, proprietary APIs) is out.
- **Email is the control plane, HTTPS is the data plane for outbound transfers.** Manifests carry references, not file bytes. Two bounded ingress conveniences are explicit exceptions: ordinary inbound email attachments and hosted MCP inline content up to 1 MiB. The local MCP bridge streams disk files over HTTPS without putting bytes in model context.
- **The canonical receipt encoding is frozen.** Anything that changes `Receipt.Canonical()` output breaks every existing chain. Don't.
- **Anonymous file surfaces stay ephemeral.** Share links and unclaimed arrivals expire. An agent app is the deliberate durable public surface: deployment requires current-mailbox `email` provenance (never `operator` or migrated `legacy`), and apps remain host-routed, quota-bound, and removable without weakening link semantics.
- **No server-side fetching of URLs from inbound mail** (SSRF). Recipients download explicitly. The resident concierge is a separately invoked authenticated client: it accepts only same-instance trusted offers, stays on the exact configured origin, rejects redirects, and enforces dial/time/byte limits. Webhook delivery validates the concrete target IP at connect time and reaches only public unicast.
- **Transfer encryption is client-side; the server never sees file plaintext or age keys.** `--encrypt`/`--seal` encrypt before upload and the server stores ciphertext only. Don't add a code path that decrypts server-side or accepts an age key over the wire. Container environment values are a separate app-runtime concern and must not be confused with this guarantee.

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
internal/server/apps.go       # app REST API, static serving, host routing, archive validation
internal/server/apps_runtime.go # typed adapter from app lifecycle to the isolated runner
internal/server/spaces.go     # spaces HTTP handlers (see docs/spaces.md)
internal/server/webhooks.go   # SSRF-safe webhook delivery worker + signing (see docs/webhooks.md)
internal/server/connect_*.go  # Connect: tunnel host + client (see docs/connect.md)
internal/store/         # SQLite + sha256-addressed blob store + receipt chain writer
internal/store/apps.go        # owner-verification provenance, apps, immutable releases, app blob refs
internal/store/cards.go       # opt-in discovery cards + directory (see docs/discovery.md)
internal/store/spaces.go      # spaces: membership + shared event-stream tables (see docs/spaces.md)
internal/store/policy.go      # recipient accept policy + quarantine (see docs/identity-and-trust.md)
internal/store/webhooks.go    # webhook + delivery-queue tables and queries
internal/receipt/       # canonical encoding, signing, chain verification
internal/apphost/       # authenticated Unix-socket runner client/server; the only Docker caller
internal/mail/          # outbound MIME build + relay submission, inbound parsing
internal/proto/         # AgentTransfer manifest types with URI-file/A2A-mappable parts
internal/seal/          # age wrappers: symmetric + sealed (X25519) streaming encryption
internal/cli/           # client commands, demo, doctor
internal/cli/apps.go    # app-deploy/status/logs/stop/rm + safe deterministic directory packaging
internal/cli/mcp.go     # the local `agenttransfer mcp` stdio bridge (see docs/mcp.md)
internal/cli/spaces.go  # the space-* CLI commands
internal/cli/crypto.go  # client-side --encrypt / --seal, identity keypair, verify-on-download
```

### Storage: migrations and blob GC

- **Schema changes go through the migration framework.** `internal/store/store.go` holds an ordered `migrations` slice; each entry runs once, in order, inside a transaction, and `PRAGMA user_version` records how many have applied. Append a new migration — **never edit a shipped one**, or existing databases skip it. Index `i` is version `i+1`: v1 base/connect/webhooks, v2 cards, v3 spaces, v4 policy, v5 public identity contact, v6 persons/fleets, v7 owner-verification provenance, v8 apps/releases, v9 durable container-history state for runner cleanup, v10 mailbox-bound verification challenges, v11 atomic shared local names, v12 request-bound idempotency records, v13 unverified owner-nomination timestamps.
- **Blobs are not reference-counted.** There is no refcount column to keep consistent. `DeleteOrphanBlobs` computes reference-ness on demand across folder files, active links, space file events, app deployment sources, and app file mappings. It runs in the janitor with a grace period so a freshly written blob isn't reaped before its first reference lands. A committed row always protects its blob. Any new blob-owning feature must extend the central predicate in the same migration/change.
- **Agent-scoped tables carry `ON DELETE CASCADE`.** Deleting an agent removes just the parent row; SQLite reaps its files, links, messages, memberships, cards, and the rest. Keep new agent-scoped tables consistent with this (and let the orphan-blob GC reclaim the bytes).

### App runtime boundary

- Static serving belongs in the public server and must work without Docker or a runner.
- The public server may speak only the typed `internal/apphost` protocol over an authenticated Unix socket. It must not shell out to Docker, accept Docker CLI fragments, mount the Docker socket, or trust a caller-supplied upstream.
- Security-sensitive runtime choices are runner-owned ceilings: serialized source builds and their network policy, loopback-only published ports, unprivileged uid/gid, read-only root, dropped capabilities, `no-new-privileges`, bounded `/tmp`, CPU/memory/PID limits, rotating logs, and a single persistent `/data` mount. Request fields describe the app (`image`, `port`, argv, env, health path), not host policy.
- Source archives remain ordinary content-addressed blobs. Validate archive paths/types before persisting a release, materialize contexts beneath public-service-owned `APP_BUILD_ROOT`, and let the runner snapshot them through descriptor-anchored handles into its separate transient `APP_SNAPSHOT_ROOT`; Docker must never read mutable public input or durable `APP_DATA_ROOT` scratch. Arbitrary source builds are an explicit operator trust opt-in. A replacement drains the old runtime before mounting shared `/data`; every failure path must remove uncertain replacements and restart plus health-check the SQLite-desired runtime. A static switch must remove every stale runtime without purging `/data`.
- Environment values may cross the in-memory server-to-runner request but must not enter SQLite, receipts, API responses, CLI/MCP output, or logs. Persist and return keys only. This is defense against accidental disclosure, not a secrets manager.
- Runner-managed resources are outside SQLite cascades. Any account/app deletion path must stop runtimes and make an explicit decision about persistent `/data`; ordinary app reset retains app id/slug and data, while purge deletes all three. Add integration tests for metadata, stale-runtime convergence, and external cleanup.

## Pull requests

- Include a test that fails without your change (the e2e suite in `internal/server/e2e_test.go` makes most behaviors easy to pin).
- `agenttransfer demo` must still pass — it's the contract with every README reader.
- Update `docs/` when you change API surface, config, or the protocol; `docs/protocol.md` is normative for interop.
- Keep error messages actionable — operators read them at 2 a.m.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please don't open public issues for vulnerabilities.
