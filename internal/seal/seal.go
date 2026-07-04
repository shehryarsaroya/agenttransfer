// Package seal is AgentTransfer's client-side file encryption. It wraps
// filippo.io/age so bytes are encrypted before they leave the machine and
// decrypted after they arrive — the server (and any operator) only ever sees
// ciphertext. Two modes:
//
//   - Symmetric ("--encrypt"): a random 128-bit key, carried out-of-band or in
//     a link fragment. age scrypt recipient; work factor kept low because the
//     key is already high-entropy (scrypt's stretching is for weak passphrases).
//   - Sealed ("--seal"): encrypted to a recipient agent's X25519 public key, so
//     only that agent can decrypt even through an untrusted operator.
//
// age gives confidentiality + integrity, NOT sender authentication: sealing to
// Bob's key proves only that the sender knew Bob's (public) key. If provable
// origin is ever needed, pair with a signature — deliberately out of scope here.
//
// Everything streams (age uses 64 KiB ChaCha20-Poly1305 STREAM chunks), so a
// 5 GB file encrypts and decrypts in constant memory.
package seal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// KeyPrefix tags a symmetric key string so tooling can recognize it.
const KeyPrefix = "atk_"

// scryptWorkFactor is intentionally low: our symmetric keys are 128-bit random,
// so the passphrase-stretching scrypt normally does is unnecessary and would
// only add latency. (age's default is 18; 10 is ample for a random key.)
const scryptWorkFactor = 10

// NewKey returns a fresh random symmetric key string ("atk_<base64url>").
func NewKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// EncryptSymmetric wraps dst so that plaintext written to the returned
// WriteCloser is encrypted under key. The caller MUST Close the writer to
// flush age's final chunk.
func EncryptSymmetric(dst io.Writer, key string) (io.WriteCloser, error) {
	r, err := age.NewScryptRecipient(key)
	if err != nil {
		return nil, fmt.Errorf("seal: bad key: %w", err)
	}
	r.SetWorkFactor(scryptWorkFactor)
	w, err := age.Encrypt(dst, r)
	if err != nil {
		return nil, fmt.Errorf("seal: encrypt: %w", err)
	}
	return w, nil
}

// DecryptSymmetric wraps src so reads return the plaintext of a symmetrically
// encrypted stream.
func DecryptSymmetric(src io.Reader, key string) (io.Reader, error) {
	id, err := age.NewScryptIdentity(key)
	if err != nil {
		return nil, fmt.Errorf("seal: bad key: %w", err)
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		return nil, fmt.Errorf("seal: decrypt (wrong key or not encrypted?): %w", err)
	}
	return r, nil
}

// Identity is an agent's X25519 keypair for sealed transfers. The private half
// never leaves the machine; the Recipient() is published.
type Identity struct {
	x *age.X25519Identity
}

// NewIdentity generates a fresh sealed-transfer keypair.
func NewIdentity() (*Identity, error) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	return &Identity{x: x}, nil
}

// ParseIdentity restores an identity from its secret string
// ("AGE-SECRET-KEY-1...").
func ParseIdentity(secret string) (*Identity, error) {
	x, err := age.ParseX25519Identity(strings.TrimSpace(secret))
	if err != nil {
		return nil, fmt.Errorf("seal: bad identity: %w", err)
	}
	return &Identity{x: x}, nil
}

// Secret returns the identity's private string ("AGE-SECRET-KEY-1..."); store
// it locally, never publish it.
func (i *Identity) Secret() string { return i.x.String() }

// Recipient returns the identity's public string ("age1..."); publish this so
// others can seal files to this agent.
func (i *Identity) Recipient() string { return i.x.Recipient().String() }

// ValidRecipient reports whether s is a well-formed "age1..." recipient.
func ValidRecipient(s string) bool {
	_, err := age.ParseX25519Recipient(strings.TrimSpace(s))
	return err == nil
}

// EncryptTo wraps dst so plaintext written to the returned WriteCloser is
// sealed to the given "age1..." recipients (only their holders can decrypt).
// The caller MUST Close the writer.
func EncryptTo(dst io.Writer, recipients ...string) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("seal: no recipients")
	}
	rs := make([]age.Recipient, 0, len(recipients))
	for _, s := range recipients {
		r, err := age.ParseX25519Recipient(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("seal: bad recipient %q: %w", s, err)
		}
		rs = append(rs, r)
	}
	w, err := age.Encrypt(dst, rs...)
	if err != nil {
		return nil, fmt.Errorf("seal: encrypt: %w", err)
	}
	return w, nil
}

// DecryptWith wraps src so reads return the plaintext of a stream sealed to
// this identity.
func (i *Identity) DecryptWith(src io.Reader) (io.Reader, error) {
	r, err := age.Decrypt(src, i.x)
	if err != nil {
		return nil, fmt.Errorf("seal: decrypt (not sealed to this agent?): %w", err)
	}
	return r, nil
}
