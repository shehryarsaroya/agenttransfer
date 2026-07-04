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

Encrypted directly to the recipient's public key, so only they can open it — no shared secret to pass around.

```sh
agenttransfer send weights.bin --to gpu-box@agenttransfer.dev --seal
```

`gpu-box` decrypts automatically; its `get` sees the offer is sealed and uses its own identity:

```sh
agenttransfer get <msg-id>          # just works — decrypts with the local identity
```

Anyone else who somehow gets the ciphertext — including the operator — cannot read it.

**Same-instance for now.** Sealing needs the recipient's public key, which the client fetches from the instance. Today that works when sender and recipient are on the same instance; a cross-instance recipient (or a human with no key) gets a clear error pointing you back to `--encrypt`. Cross-instance key discovery is on the roadmap.

## Keys

Every agent gets an [X25519](https://age-encryption.org) keypair the first time it logs in. The public half (`age1…`) is published to the instance so others can seal files to it; the private half (`AGE-SECRET-KEY-1…`) is written to your client config and **never leaves the machine**. Re-logging in keeps the same identity, and rotating your API key doesn't touch it.

If you run headless (env vars, or the MCP bridge), set `AGENTTRANSFER_IDENTITY` to the secret so you can decrypt sealed files there too.

## What's verified, and what isn't

- **Integrity travels without the key.** The sha256 in an offer is over the *ciphertext*, so any receiver — and the operator — can confirm the bytes weren't corrupted in transit, without being able to read them. age's own authentication (a per-chunk tag) independently catches tampering: a modified or truncated file fails to decrypt rather than producing garbage.
- **A downgrade is visible.** The "this file is encrypted" hint rides in the manifest, which the operator relays and could strip. If it's stripped and you don't pass a key, the CLI notices the downloaded bytes are an age stream and tells you it's raw ciphertext — it won't hand you an undecryptable file under a "verified" banner.
- **What sealing does *not* prove: who sent it.** Encrypting to Bob's public key shows the sender knew Bob's (public) key — nothing more. Sealing guarantees *only Bob can read it*, not *Alice sent it*. If you need provable origin, that's a signature on top, which AgentTransfer doesn't add yet.

## What the operator can see

With encryption on, the operator sees ciphertext, its size, its sha256, the sender and recipient addresses, and the timing — the metadata, not the contents. Without encryption, they can also read the file. Either way, the strongest option remains running the instance yourself (or via `serve --connect`, where the bytes stay on your machine).
