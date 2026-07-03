# Contributing to AgentTransfer

Thanks for helping build file transfer for AI agents.

## Ground rules

- **One binary, no cgo, minimal deps.** The whole pitch is `scp` a static binary to a $5 VPS. New dependencies need a strong reason; platform lock-in (managed queues, proprietary APIs) is out.
- **Email is the control plane, HTTPS is the data plane.** Bytes never ride through email or MCP tool calls; identity and notification never require a custom registry.
- **The canonical receipt encoding is frozen.** Anything that changes `Receipt.Canonical()` output breaks every existing chain. Don't.
- **Public surface stays ephemeral.** Share links and unclaimed arrivals expire; features that make unauthenticated data live forever will be declined.
- **No server-side fetching of URLs from inbound mail** (SSRF). Recipients download explicitly.

## Dev loop

```sh
make test    # unit + end-to-end (httptest) suite
make demo    # the 30-second story; also CI's smoke test
make lint    # gofmt + go vet — CI enforces both
```

Layout:

```
main.go                 # subcommand dispatch
internal/server/        # HTTP API, MCP, share pages, inbound SMTP, janitor, config
internal/server/connect_*.go  # Connect: tunnel host + client (see docs/connect.md)
internal/store/         # SQLite + sha256-addressed blob store + receipt chain writer
internal/receipt/       # canonical encoding, signing, chain verification
internal/mail/          # outbound MIME build + relay submission, inbound parsing
internal/proto/         # the A2A-aligned manifest types
internal/cli/           # client commands, demo, doctor
```

## Pull requests

- Include a test that fails without your change (the e2e suite in `internal/server/e2e_test.go` makes most behaviors easy to pin).
- `agenttransfer demo` must still pass — it's the contract with every README reader.
- Update `docs/` when you change API surface, config, or the protocol; `docs/protocol.md` is normative for interop.
- Keep error messages actionable — operators read them at 2 a.m.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please don't open public issues for vulnerabilities.
