package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

// saveConfig writes the client config (0600) to the OS user-config dir,
// creating the directory. Centralized so every writer preserves all fields
// (notably the sealed-transfer Identity, which rotate-key must not drop).
func saveConfig(c clientConfig) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	buf, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		return err
	}
	// WriteFile's mode only applies when creating; tighten an existing file too
	// (it holds the API key + the sealed-transfer secret).
	return os.Chmod(p, 0o600)
}

// ensureIdentity returns this login's sealed-transfer identity, generating and
// persisting one on first use. It (re)publishes the public key to the instance
// on EVERY call, best-effort: publishing is idempotent, so re-running login
// self-heals a publish that failed earlier (a flaky first login otherwise left
// the agent permanently unable to receive sealed files). A publish error never
// blocks login. Returns an error only if key generation/parsing fails.
func ensureIdentity(a *api, c *clientConfig) (*seal.Identity, error) {
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
func resolveRecipientKeys(a *api, recipients []string) ([]string, error) {
	// Instance domain, to reject cross-instance recipients up front.
	var who struct {
		Instance string `json:"instance"`
		Pubkey   string `json:"pubkey"`
	}
	if err := a.json("GET", "/v1/whoami", nil, &who); err != nil {
		return nil, err
	}
	instance := who.Instance
	keys := map[string]bool{}
	if who.Pubkey != "" {
		keys[who.Pubkey] = true // sender can decrypt their own sent file
	}
	for _, r := range recipients {
		local, domain, ok := splitAddr(r)
		if !ok {
			return nil, fmt.Errorf("--seal: %q is not an address", r)
		}
		if domain != instance {
			return nil, fmt.Errorf("--seal is same-instance only for now; %q is on another instance — use --encrypt (a shared key) for cross-instance or human recipients", r)
		}
		var pk struct {
			Pubkey string `json:"pubkey"`
		}
		if err := a.json("GET", "/v1/agents/"+local+"/pubkey", nil, &pk); err != nil {
			return nil, fmt.Errorf("--seal: %q has not published a sealed-transfer key (they must log in with a current build) — use --encrypt instead", r)
		}
		keys[pk.Pubkey] = true
	}
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, nil
}

// splitAddr splits "name@domain" (lowercased) into its parts.
func splitAddr(addr string) (local, domain string, ok bool) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	local, domain, ok = strings.Cut(addr, "@")
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
func verifyAndDecrypt(src io.Reader, dest, wantCipherSHA, key string, id *seal.Identity) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".agenttransfer-*")
	if err != nil {
		return err
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
		return err
	}
	if _, err := io.Copy(tmp, pt); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if wantCipherSHA != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, wantCipherSHA) {
			return fmt.Errorf("ciphertext sha256 mismatch: got %s want %s — refusing the file", got, wantCipherSHA)
		}
	}
	return os.Rename(tmp.Name(), dest)
}
