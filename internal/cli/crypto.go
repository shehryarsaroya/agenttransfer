package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

// saveConfig writes the client config (0600) to the OS user-config dir,
// creating the directory. Centralized so every writer preserves all fields
// (notably the sealed-transfer Identity, which rotate-key must not drop).
func saveConfig(c clientConfig) error {
	rememberActiveIdentity(&c)
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Write a complete replacement beside the config, then atomically rename it
	// into place. A full disk or interrupted write must not truncate the only
	// copy of an API key or sealed-transfer identity.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

// normalizedBase is the stable origin/account namespace used for local key
// material. It intentionally keeps any path prefix because two installations
// can share one scheme+host behind different prefixes.
func normalizedBase(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func sameLogin(a, b clientConfig) bool {
	return normalizedBase(a.URL) == normalizedBase(b.URL) && a.APIKey != "" && a.APIKey == b.APIKey
}

func identitySlot(base, agentID string) string {
	if strings.TrimSpace(agentID) == "" {
		return ""
	}
	return normalizedBase(base) + "#agent=" + strings.TrimSpace(agentID)
}

func cloneIdentities(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func clonePins(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func activeIdentity(c clientConfig) string {
	if slot := identitySlot(c.URL, c.AgentID); slot != "" && c.Identities != nil {
		if secret := strings.TrimSpace(c.Identities[slot]); secret != "" {
			return secret
		}
	}
	return strings.TrimSpace(c.Identity)
}

func rememberActiveIdentity(c *clientConfig) {
	secret := strings.TrimSpace(c.Identity)
	if secret == "" {
		return
	}
	slot := identitySlot(c.URL, c.AgentID)
	if slot == "" {
		return
	}
	if c.Identities == nil {
		c.Identities = make(map[string]string)
	}
	c.Identities[slot] = secret
}

// carryKeyHistory retains inactive account identities and TOFU pins while
// switching logins, without assigning the previous account's active identity
// to the new account.
func carryKeyHistory(dst *clientConfig, prev clientConfig) {
	rememberActiveIdentity(&prev)
	dst.Identities = cloneIdentities(prev.Identities)
	dst.RecipientPins = clonePins(prev.RecipientPins)
}

// clearDeletedLogin removes only the deleted account's active credentials and
// key state. Other account identities/pins remain available for a later login;
// deleting the whole multi-account config would orphan their sealed files.
func clearDeletedLogin(c clientConfig) error {
	slot := identitySlot(c.URL, c.AgentID)
	if slot != "" {
		delete(c.Identities, slot)
		pinPrefix := slot + "#recipient="
		for key := range c.RecipientPins {
			if strings.HasPrefix(key, pinPrefix) {
				delete(c.RecipientPins, key)
			}
		}
	}
	c.URL = ""
	c.APIKey = ""
	c.AgentID = ""
	c.AgentEmail = ""
	c.Identity = ""
	if len(c.Identities) == 0 && len(c.RecipientPins) == 0 {
		p, err := configPath()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return saveConfig(c)
}

func recipientPinSlot(c clientConfig, recipient string) string {
	scope := identitySlot(c.URL, c.AgentID)
	if scope == "" {
		// Environment-only legacy configs may not know the agent id. Hash the
		// bearer key to isolate pins without persisting the credential itself.
		h := sha256.Sum256([]byte(c.APIKey))
		scope = normalizedBase(c.URL) + "#key=" + hex.EncodeToString(h[:8])
	}
	return scope + "#recipient=" + strings.ToLower(strings.TrimSpace(recipient))
}

func newIdempotencyKey() (string, error) {
	return idempotencyKeyFrom(rand.Reader)
}

func prepareIdempotencyKey(raw string) (string, error) {
	return prepareIdempotencyKeyWith(raw, newIdempotencyKey)
}

func prepareIdempotencyKeyWith(raw string, generate func() (string, error)) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		var err error
		key, err = generate()
		if err != nil {
			return "", err
		}
	}
	if key == "" || len(key) > 128 {
		return "", errors.New("idempotency key must be 1-128 visible ASCII characters")
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return "", errors.New("idempotency key must contain only visible ASCII characters without spaces")
		}
	}
	return key, nil
}

func idempotencyKeyFrom(random io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("generate idempotency key: %w", err)
	}
	return "cli_" + hex.EncodeToString(b), nil
}

// ensureIdentity returns this login's sealed-transfer identity, generating and
// persisting one on first use. It (re)publishes the public key to the instance
// on EVERY call, best-effort: publishing is idempotent, so re-running login
// self-heals a publish that failed earlier (a flaky first login otherwise left
// the agent permanently unable to receive sealed files). A publish error never
// blocks login. Returns an error only if key generation/parsing fails.
func ensureIdentity(a *api, c *clientConfig) (*seal.Identity, error) {
	c.Identity = activeIdentity(*c)
	if c.Identity == "" {
		id, err := seal.NewIdentity()
		if err != nil {
			return nil, err
		}
		c.Identity = id.Secret()
		if err := saveConfig(*c); err != nil {
			return nil, err
		}
	}
	id, err := seal.ParseIdentity(c.Identity)
	if err != nil {
		return nil, err
	}
	_ = a.json("POST", "/v1/agents/self/settings", map[string]any{"pubkey": id.Recipient()}, nil)
	return id, nil
}

// resolveRecipientKeys fetches the published sealed-transfer key ("age1...")
// for each recipient so a --seal send can encrypt to all of them. MVP scope is
// same-instance: the lookup runs against the sender's own instance, so a
// cross-instance recipient (or one who hasn't published a key) fails with a
// clear pointer to --encrypt. The sender's own key is added too so the sender
// can still read what they sent.
func resolveRecipientKeys(a *api, c *clientConfig, recipients []string, repin bool) ([]string, []string, error) {
	// Instance domain, to reject cross-instance recipients up front.
	var who struct {
		Instance string `json:"instance"`
		Email    string `json:"email"`
	}
	if err := a.json("GET", "/v1/whoami", nil, &who); err != nil {
		return nil, nil, err
	}
	instance := who.Instance
	keys := map[string]bool{}
	// Derive the sender recipient from the local secret. Trusting whoami's
	// public value would let an active operator add its own key and decrypt
	// every sealed upload even when all recipient pins matched.
	self, err := loadIdentity(*c)
	if err != nil {
		return nil, nil, fmt.Errorf("--seal: load your local identity: %w", err)
	}
	keys[self.Recipient()] = true
	pins := clonePins(c.RecipientPins)
	changedPins := false
	var notes []string
	selfLocal, _, selfOK := splitAddr(c.AgentEmail)
	if !selfOK {
		selfLocal, _, selfOK = splitAddr(who.Email)
	}
	for _, r := range recipients {
		local, domain, ok := splitAddr(r)
		if !ok {
			return nil, nil, fmt.Errorf("--seal: %q is not an address", r)
		}
		if domain != instance {
			return nil, nil, fmt.Errorf("--seal is same-instance only for now; %q is on another instance — use --encrypt (a shared key) for cross-instance or human recipients", r)
		}
		addr := local + "@" + domain
		if selfOK && local == selfLocal {
			// The local secret is authoritative for the sender's own recipient.
			// Consulting the server's directory for a self-send would let a
			// substituted directory key become an additional decryptor.
			continue
		}
		var pk struct {
			Pubkey string `json:"pubkey"`
		}
		if err := a.json("GET", "/v1/agents/"+url.PathEscape(local)+"/pubkey", nil, &pk); err != nil {
			return nil, nil, fmt.Errorf("--seal: %q has not published a sealed-transfer key (they must log in with a current build) — use --encrypt instead", r)
		}
		pk.Pubkey = strings.TrimSpace(pk.Pubkey)
		if !seal.ValidRecipient(pk.Pubkey) {
			return nil, nil, fmt.Errorf("--seal: %q returned an invalid X25519 recipient", r)
		}
		slot := recipientPinSlot(*c, addr)
		old := strings.TrimSpace(pins[slot])
		switch {
		case old == "":
			if pins == nil {
				pins = make(map[string]string)
			}
			pins[slot] = pk.Pubkey
			changedPins = true
			notes = append(notes, fmt.Sprintf("TOFU-pinned %s as %s", addr, pk.Pubkey))
		case old != pk.Pubkey && !repin:
			return nil, nil, fmt.Errorf("--seal: SECURITY: recipient key for %s changed\n  pinned: %s\n  offered: %s\nverify the change with the recipient, then retry with --repin", addr, old, pk.Pubkey)
		case old != pk.Pubkey:
			pins[slot] = pk.Pubkey
			changedPins = true
			notes = append(notes, fmt.Sprintf("re-pinned %s as %s", addr, pk.Pubkey))
		}
		keys[pk.Pubkey] = true
	}
	if changedPins {
		next := *c
		next.RecipientPins = pins
		if err := persistKeyState(next); err != nil {
			return nil, nil, fmt.Errorf("--seal: cannot persist recipient key pins; refusing to encrypt: %w", err)
		}
		c.RecipientPins = pins
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, notes, nil
}

// persistKeyState updates the normal config only when it represents this same
// login. Environment-only credentials must not overwrite an unrelated saved
// login or silently persist a bearer key merely to store TOFU pins.
func persistKeyState(c clientConfig) error {
	if strings.TrimSpace(os.Getenv("AGENTTRANSFER_URL")) == "" || strings.TrimSpace(os.Getenv("AGENTTRANSFER_KEY")) == "" {
		return saveConfig(c)
	}
	fc, err := readFileConfig()
	if err != nil || !sameLogin(fc, c) {
		return fmt.Errorf("environment-only login has no matching saved config; run `agenttransfer login %s --key ...` first", c.URL)
	}
	// Persist only the pin state being changed. AGENTTRANSFER_IDENTITY is an
	// in-process override; using it for one MCP/CLI session must not replace the
	// saved account identity and orphan ciphertext addressed to that key.
	fc.RecipientPins = clonePins(c.RecipientPins)
	return saveConfig(fc)
}

// splitAddr splits "name@domain" (lowercased) into its parts.
func splitAddr(addr string) (local, domain string, ok bool) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	local, domain, ok = strings.Cut(addr, "@")
	ok = ok && local != "" && domain != "" && !strings.Contains(domain, "@")
	return local, domain, ok
}

// loadIdentity resolves the local sealed-transfer identity for decrypting
// sealed files: from AGENTTRANSFER_IDENTITY, else the config file.
func loadIdentity(c clientConfig) (*seal.Identity, error) {
	secret := strings.TrimSpace(os.Getenv("AGENTTRANSFER_IDENTITY"))
	if secret == "" {
		secret = c.Identity
	}
	if secret == "" {
		return nil, fmt.Errorf("no sealed-transfer identity on this machine — log in again to generate one")
	}
	return seal.ParseIdentity(secret)
}

// encryptingReader streams the file at path through age, returning a reader of
// ciphertext for upload. mode is proto.EncSymmetric (uses key) or
// proto.EncSealed (uses recipients). Encryption runs in a goroutine feeding an
// io.Pipe, so a 5 GB file never lands in memory. Close the returned ReadCloser.
func encryptingReader(path, key string, recipients []string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		defer f.Close()
		var enc io.WriteCloser
		var e error
		if len(recipients) > 0 {
			enc, e = seal.EncryptTo(pw, recipients...)
		} else {
			enc, e = seal.EncryptSymmetric(pw, key)
		}
		if e != nil {
			pw.CloseWithError(e)
			return
		}
		if _, e := io.Copy(enc, f); e != nil {
			pw.CloseWithError(e)
			return
		}
		if e := enc.Close(); e != nil { // flush age's final chunk
			pw.CloseWithError(e)
			return
		}
		pw.Close()
	}()
	return pr, nil
}

// verifyAndDecrypt reads ciphertext from src, verifies its sha256 matches
// wantCipherSHA (the offer's hash is over ciphertext, so integrity is checkable
// without the key), decrypts to a temp file next to dest, and renames into
// place. key set → symmetric; id set → sealed. age's AEAD independently
// guarantees plaintext integrity, so a tampered stream fails to decrypt.
func verifyAndDecrypt(src io.Reader, dest, wantCipherSHA, key string, id *seal.Identity, explicitDest bool) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".agenttransfer-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	h := sha256.New()
	ct := io.TeeReader(src, h) // hashing the ciphertext as the decryptor consumes it

	var pt io.Reader
	if id != nil {
		pt, err = id.DecryptWith(ct)
	} else {
		pt, err = seal.DecryptSymmetric(ct, key)
	}
	if err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := io.Copy(tmp, pt); err != nil {
		tmp.Close()
		return "", err
	}
	// Hash the complete ciphertext response, not merely the bytes the decryptor
	// happened to consume before reporting plaintext EOF. age currently rejects
	// trailing data, but draining here keeps the digest contract correct for any
	// reader buffering behavior and propagates a late transport error.
	if _, err := io.Copy(io.Discard, ct); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if wantCipherSHA != "" {
		if !strings.EqualFold(got, wantCipherSHA) {
			return got, fmt.Errorf("ciphertext sha256 mismatch: got %s want %s — refusing the file", got, wantCipherSHA)
		}
	}
	if err := commitDownloadedFile(tmp.Name(), dest, explicitDest); err != nil {
		return got, err
	}
	return got, nil
}
