package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

func TestSafeImplicitDownloadName(t *testing.T) {
	tests := map[string]string{
		"../../.ssh/authorized_keys":            "authorized_keys",
		`C:\Windows\System32\drivers\etc\hosts`: "hosts",
		"/etc/passwd":                           "passwd",
		".bashrc":                               "download.bashrc",
		"NUL.txt":                               "_NUL.txt",
		"report:alternate-stream.pdf":           "report_alternate-stream.pdf",
		"invoice\u202Efdp.exe":                  "invoice_fdp.exe",
		"../\x00bad\nname.txt":                  "_bad_name.txt",
		"":                                      "download.bin",
		strings.Repeat("a", 250) + ".txt":       strings.Repeat("a", 200),
		`..\..\Users\victim\.ssh\authorized_keys`:   "authorized_keys",
		`\\server\share\sensitive\credentials.json`: "credentials.json",
	}
	for raw, want := range tests {
		if got := safeImplicitDownloadName(raw); got != want {
			t.Errorf("safeImplicitDownloadName(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestContentDispositionFilenameIsSanitizedBeforeImplicitUse(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Content-Disposition": {`attachment; filename="../../.ssh/authorized_keys"`}}}
	raw := nameFromResponse(resp, "https://agents.test/f/token")
	if got := safeImplicitDownloadName(raw); got != "authorized_keys" {
		t.Fatalf("sanitized Content-Disposition = %q", got)
	}
}

func TestImplicitDownloadNeverOverwrites(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("report.txt", []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(".", ".download-*")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tmp.WriteString("attacker")
	_ = tmp.Close()
	defer os.Remove(tmp.Name())

	if err := commitDownloadedFile(tmp.Name(), "report.txt", false); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("implicit overwrite error = %v", err)
	}
	got, _ := os.ReadFile("report.txt")
	if string(got) != "original" {
		t.Fatalf("existing file changed to %q", got)
	}
}

func TestExplicitDownloadMayReplaceDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tmp.WriteString("replacement")
	_ = tmp.Close()
	if err := commitDownloadedFile(tmp.Name(), dest, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "replacement" {
		t.Fatalf("explicit destination = %q", got)
	}
}

func TestEncryptedImplicitDownloadNeverOverwrites(t *testing.T) {
	t.Chdir(t.TempDir())
	key, err := seal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	w, err := seal.EncryptSymmetric(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("verified plaintext"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ciphertext.Bytes())
	if err := os.WriteFile("secret.txt", []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verifyAndDecrypt(bytes.NewReader(ciphertext.Bytes()), "secret.txt", hex.EncodeToString(sum[:]), key, nil, false)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("encrypted implicit overwrite error = %v", err)
	}
	got, _ := os.ReadFile("secret.txt")
	if string(got) != "original" {
		t.Fatalf("existing encrypted destination changed to %q", got)
	}

	if _, err := verifyAndDecrypt(bytes.NewReader(ciphertext.Bytes()), "secret.txt", hex.EncodeToString(sum[:]), key, nil, true); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile("secret.txt")
	if string(got) != "verified plaintext" {
		t.Fatalf("explicit decrypted destination = %q", got)
	}
}
