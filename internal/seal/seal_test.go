package seal

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestSymmetricRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, KeyPrefix) {
		t.Fatalf("key %q missing prefix", key)
	}
	plain := bytes.Repeat([]byte("secret payload "), 10000) // ~150 KB, multi-chunk

	var ct bytes.Buffer
	w, err := EncryptSymmetric(&ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Bytes(), []byte("secret payload")) {
		t.Fatal("ciphertext contains plaintext")
	}

	r, err := DecryptSymmetric(&ct, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip mismatch")
	}

	// Wrong key must fail, not silently return garbage.
	wrongKey, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := DecryptSymmetric(bytes.NewReader(ct.Bytes()), wrongKey)
	if r2 != nil {
		if _, err := io.ReadAll(r2); err == nil {
			t.Fatal("wrong key decrypted without error")
		}
	}
}

func TestSymmetricKeyGenerationReturnsEntropyFailure(t *testing.T) {
	key, err := newKeyFrom(strings.NewReader(strings.Repeat("x", 16)))
	if err != nil || key != KeyPrefix+"eHh4eHh4eHh4eHh4eHh4eA" {
		t.Fatalf("deterministic key = %q err=%v", key, err)
	}
	if _, err := newKeyFrom(strings.NewReader("short")); err == nil || !strings.Contains(err.Error(), "generate symmetric key") {
		t.Fatalf("short entropy error = %v", err)
	}
}

func TestSealedRoundTrip(t *testing.T) {
	bob, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidRecipient(bob.Recipient()) {
		t.Fatalf("bob recipient invalid: %q", bob.Recipient())
	}
	if !strings.HasPrefix(bob.Secret(), "AGE-SECRET-KEY-1") || !strings.HasPrefix(bob.Recipient(), "age1") {
		t.Fatalf("odd key strings: %q / %q", bob.Secret(), bob.Recipient())
	}
	plain := []byte("model weights for bob only")

	var ct bytes.Buffer
	w, err := EncryptTo(&ct, bob.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plain)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Bob decrypts.
	r, err := bob.DecryptWith(bytes.NewReader(ct.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, plain) {
		t.Fatal("sealed round trip mismatch")
	}

	// A different identity (carol) must not decrypt bob's file.
	carol, _ := NewIdentity()
	if r2, err := carol.DecryptWith(bytes.NewReader(ct.Bytes())); err == nil {
		if _, err := io.ReadAll(r2); err == nil {
			t.Fatal("carol decrypted a file sealed to bob")
		}
	}
}

func TestIdentityParseRoundTrip(t *testing.T) {
	id, _ := NewIdentity()
	back, err := ParseIdentity(id.Secret())
	if err != nil {
		t.Fatal(err)
	}
	if back.Recipient() != id.Recipient() {
		t.Fatal("identity parse round trip changed the recipient")
	}
	if _, err := ParseIdentity("not-a-key"); err == nil {
		t.Fatal("parsed a bogus identity")
	}
	if ValidRecipient("age1nonsense") {
		t.Fatal("accepted a bogus recipient")
	}
}
