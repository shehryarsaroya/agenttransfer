# Encryption

By default AgentTransfer does not encrypt file contents: bytes are stored as you upload them, and the operator of the instance can read them. That's the right default when you run the instance yourself — you *are* the operator. It stops being right when you route a file through someone else's instance and don't want them to see it.

For that, AgentTransfer can encrypt on the client, before anything leaves your machine. It's built on [age](https://github.com/FiloSottile/age): a small, well-regarded encryption tool by the maintainer of Go's crypto library. It streams, so a 5 GB file encrypts and decrypts in constant memory, and the server only ever holds ciphertext.

There are two modes.

## Symmetric — `--encrypt`

A random key encrypts the file; you pass the key to the recipient however you already talk to them.

```sh
agenttransfer put report.pdf --encrypt --share
#   🔒 report.pdf encrypted and uploaded — sha256:… (ciphertext)
#     key: atk_9fK2…
#     link: https://…/f/…

agenttransfer send report.pdf --to dana@gmail.com --encrypt
#   prints the key for you to hand over out-of-band
```

The recipient supplies the key on the way down:

```sh
agenttransfer get <msg-id-or-url> --key atk_9fK2…
```

**Why the key travels separately.** If you put the key *in* the link, then anyone who gets the link gets the file — one leaked message and it's over. Handing the key over on a different channel means an attacker needs both. So `--encrypt` prints the key for you to share out-of-band rather than baking it into the URL.

Use symmetric encryption for humans (who have no key of their own) and for cross-instance sends.

## Sealed — `--seal`

Encrypted directly to the recipient's pinned public key, so holders of the corresponding private keys can open it — no shared secret to pass around.

```sh
agenttransfer send weights.bin --to gpu-box@agents.example.com --seal
```

`gpu-box` decrypts automatically; its `get` sees the offer is sealed and uses its own identity:

```sh
agenttransfer get <msg-id>          # just works — decrypts with the local identity
```

Without `-o`, encrypted and plaintext `get` use the same safe commit rule: an
untrusted manifest/header name is reduced to one visible basename in the
current directory, and an existing entry is never replaced. Supplying
`-o PATH` explicitly authorizes that destination and replacement behavior.

The sender includes its own locally derived recipient so it can retain access; it never trusts a server-supplied copy of its own key. For other recipients, the CLI uses trust on first use (TOFU): the first key seen for an instance/account/recipient is stored locally, and a later change is refused with both old and new public keys. After independently confirming a legitimate rotation with the recipient, retry with `--repin` (or MCP `repin:true`).

TOFU has a precise limit: an active instance operator can substitute a recipient key on the *first* contact, before a sender has any trusted pin. Once a correct key is pinned, silent substitution is detected. Use `--encrypt` with a key shared over an independent authenticated channel when even first-contact directory trust is unacceptable.

**Same-instance for now.** Sealing needs the recipient's public key, which the client fetches from the instance. Today that works when sender and recipient are on the same instance; a cross-instance recipient (or a human with no key) gets a clear error pointing you back to `--encrypt`. Cross-instance key discovery is on the roadmap.

## Keys

Every instance account gets its own [X25519](https://age-encryption.org) keypair the first time it logs in. The public half (`age1…`) is published to the instance so others can seal files to it; the private half (`AGE-SECRET-KEY-1…`) is written to the atomic, mode-`0600` client config and **never leaves the machine**. Switching accounts selects a distinct identity; re-logging into the same instance account reuses that account's identity, and rotating its API key doesn't touch it.

If you run headless, `AGENTTRANSFER_IDENTITY` selects the private key for
decryption. A sealed send also needs durable recipient pins: run
`agenttransfer login URL --key KEY` once, then launch MCP with that exact URL
and key so it can load and update the matching account's pin set. An unrelated
environment-only login is deliberately not allowed to borrow another account's
identity or silently create non-persistent TOFU state.

## What's verified, and what isn't

- **Integrity travels without the key.** The sha256 in an offer is over the *ciphertext*, so any receiver — and the operator — can confirm the bytes weren't corrupted in transit, without being able to read them. age's own authentication (a per-chunk tag) independently catches tampering: a modified or truncated file fails to decrypt rather than producing garbage.
- **A downgrade is visible.** The "this file is encrypted" hint rides in the manifest, which the operator relays and could strip. If it's stripped and you don't pass a key, the CLI notices the downloaded bytes are an age stream and tells you it's raw ciphertext — it won't hand you an undecryptable file under a "verified" banner.
- **What sealing does *not* prove: who sent it.** Encrypting to Bob's public key shows the sender knew a key pinned for Bob — nothing more. It does not prove Alice sent the ciphertext. If you need provable origin, add a sender signature at the application layer.

## What the operator can see

With encryption on, the storage operator sees ciphertext, its size, its sha256, sender/recipient addresses, and timing. Symmetric mode with an independently shared key protects contents from an active operator. Sealed mode protects against passive storage access and, after a correct TOFU pin exists, detects later directory-key substitution; it cannot defeat malicious substitution on first contact. Without encryption the operator can read the file. A Connect host also terminates public TLS and can observe proxied traffic, so choose one you trust or run it yourself.
