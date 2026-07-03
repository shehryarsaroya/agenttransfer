// Package receipt implements AgentTransfer's signed, hash-chained receipts.
//
// Every action (upload, send, receive, download, revoke, burn, expire) writes
// one receipt. Receipts are ed25519-signed by the instance and chained: each
// carries the sha256 of the previous receipt's canonical encoding. Signatures
// prove who did what; the chain proves nothing was quietly deleted. Anyone
// holding the instance public key (published at /.well-known/agenttransfer) can
// verify offline.
package receipt

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// GenesisPrev anchors the first receipt of an instance chain.
const GenesisPrev = "genesis"

// Actions.
const (
	ActionUploaded   = "uploaded"
	ActionSent       = "sent"
	ActionReceived   = "received"
	ActionDownloaded = "downloaded"
	ActionRevoked    = "revoked"
	ActionBurned     = "burned"
	ActionExpired    = "expired"
	ActionDeleted    = "deleted"
)

// Receipt is one row of evidence.
type Receipt struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	TS        string `json:"ts"` // RFC3339Nano, UTC
	Instance  string `json:"instance"`
	Actor     string `json:"actor"` // agent email, or "system"
	Action    string `json:"action"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Target    string `json:"target,omitempty"` // counterparty: recipient/sender/link token
	MessageID string `json:"message_id,omitempty"`
	Prev      string `json:"prev"`
	Sig       string `json:"sig,omitempty"`
}

// Canonical returns the canonical JSON encoding of the receipt minus its
// signature: keys sorted, no whitespace, zero-value optional fields omitted.
// This exact byte string is what gets signed and what the chain hashes —
// changing it breaks every existing chain, so don't.
func (r Receipt) Canonical() []byte {
	m := map[string]any{
		"v":        r.V,
		"id":       r.ID,
		"ts":       r.TS,
		"instance": r.Instance,
		"actor":    r.Actor,
		"action":   r.Action,
		"prev":     r.Prev,
	}
	if r.SHA256 != "" {
		m["sha256"] = r.SHA256
	}
	if r.Size != 0 {
		m["size"] = r.Size
	}
	if r.Target != "" {
		m["target"] = r.Target
	}
	if r.MessageID != "" {
		m["message_id"] = r.MessageID
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		switch v := m[k].(type) {
		case string:
			vb, _ := json.Marshal(v)
			b.Write(vb)
		case int:
			b.WriteString(strconv.Itoa(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		default:
			vb, _ := json.Marshal(v)
			b.Write(vb)
		}
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// Hash is the chain hash of this receipt: hex sha256 over Canonical().
func (r Receipt) Hash() string {
	h := sha256.Sum256(r.Canonical())
	return hex.EncodeToString(h[:])
}

// Sign sets Sig over the canonical encoding.
func (r *Receipt) Sign(key ed25519.PrivateKey) {
	r.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, r.Canonical()))
}

// Verify checks the signature against the instance public key.
func (r Receipt) Verify(pub ed25519.PublicKey) error {
	if r.Sig == "" {
		return fmt.Errorf("receipt %s: unsigned", r.ID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Sig)
	if err != nil {
		return fmt.Errorf("receipt %s: bad signature encoding: %w", r.ID, err)
	}
	if !ed25519.Verify(pub, r.Canonical(), sig) {
		return fmt.Errorf("receipt %s: signature invalid", r.ID)
	}
	return nil
}

// VerifyChain checks the signature on every receipt. When contiguous is true
// (a full instance export, oldest first), it also checks that each prev
// equals the hash of the receipt before it, and that the chain starts at
// genesis.
func VerifyChain(rs []Receipt, pub ed25519.PublicKey, contiguous bool) error {
	for i, r := range rs {
		if err := r.Verify(pub); err != nil {
			return err
		}
		if !contiguous || i == 0 {
			continue
		}
		if r.Prev != rs[i-1].Hash() {
			return fmt.Errorf("chain broken at %s: prev does not match hash of %s", r.ID, rs[i-1].ID)
		}
	}
	if contiguous && len(rs) > 0 && rs[0].Prev != GenesisPrev {
		return fmt.Errorf("chain does not start at genesis (first prev = %q)", rs[0].Prev)
	}
	return nil
}

// ReadJSONL parses receipts from a JSON-lines stream.
func ReadJSONL(r io.Reader) ([]Receipt, error) {
	var out []Receipt
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec Receipt
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("bad receipt line: %w", err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// ParsePublicKey parses an "ed25519:<base64url>" public key string.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "ed25519:")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad public key size")
	}
	return ed25519.PublicKey(b), nil
}

// FormatPublicKey renders a public key as "ed25519:<base64url>".
func FormatPublicKey(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(pub)
}
