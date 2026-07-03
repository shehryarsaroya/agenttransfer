package receipt

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func TestCanonicalDeterministic(t *testing.T) {
	r := Receipt{V: 1, ID: "rcp_a", TS: "2026-07-02T10:00:00Z", Instance: "local",
		Actor: "alice@local", Action: "uploaded", SHA256: "ab", Size: 42, Prev: GenesisPrev}
	a, b := string(r.Canonical()), string(r.Canonical())
	if a != b {
		t.Fatalf("canonical not deterministic")
	}
	if strings.Contains(a, "sig") {
		t.Fatalf("canonical must not contain the signature: %s", a)
	}
	if !strings.HasPrefix(a, `{"action":"uploaded",`) {
		t.Fatalf("keys not sorted: %s", a)
	}
	// Zero-value optional fields must be omitted.
	r2 := Receipt{V: 1, ID: "rcp_b", TS: "t", Instance: "local", Actor: "a", Action: "sent", Prev: "p"}
	if strings.Contains(string(r2.Canonical()), "sha256") || strings.Contains(string(r2.Canonical()), "size") {
		t.Fatalf("zero optionals must be omitted: %s", r2.Canonical())
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv := testKey(t)
	r := Receipt{V: 1, ID: "rcp_a", TS: "t", Instance: "local", Actor: "a", Action: "sent", Prev: GenesisPrev}
	r.Sign(priv)
	if err := r.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	r.Action = "received" // tamper
	if err := r.Verify(pub); err == nil {
		t.Fatalf("tampered receipt verified")
	}
}

func TestVerifyChain(t *testing.T) {
	pub, priv := testKey(t)
	var rs []Receipt
	prev := GenesisPrev
	for i := 0; i < 5; i++ {
		r := Receipt{V: 1, ID: "rcp_" + string(rune('a'+i)), TS: "t", Instance: "local",
			Actor: "alice@local", Action: "uploaded", Prev: prev}
		r.Sign(priv)
		rs = append(rs, r)
		prev = r.Hash()
	}
	if err := VerifyChain(rs, pub, true); err != nil {
		t.Fatalf("chain: %v", err)
	}
	// Delete a middle receipt → chain must break.
	gapped := append(append([]Receipt{}, rs[:2]...), rs[3:]...)
	if err := VerifyChain(gapped, pub, true); err == nil {
		t.Fatalf("deleted receipt went undetected")
	}
	// Slice (non-contiguous) verification checks signatures only.
	if err := VerifyChain(gapped, pub, false); err != nil {
		t.Fatalf("slice verify should pass on valid signatures: %v", err)
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	pub, _ := testKey(t)
	s := FormatPublicKey(pub)
	got, err := ParsePublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) {
		t.Fatalf("round trip mismatch")
	}
	if _, err := ParsePublicKey("ed25519:bogus!"); err == nil {
		t.Fatalf("bad key parsed")
	}
}
