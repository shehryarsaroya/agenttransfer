package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/server"
)

// Demo runs the 30-second local end-to-end story: spin a throwaway server,
// create two agents, hand a file from one to the other, verify the hash, and
// verify the signed receipt chain. No domain, no email key, no config.
//
// It doubles as the end-to-end smoke test in CI.
func Demo(out io.Writer) error {
	step := func(format string, args ...any) { fmt.Fprintf(out, format+"\n", args...) }

	dir, err := os.MkdirTemp("", "agenttransfer-demo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	cfg := server.Config{DataDir: dir, Metrics: "off"}
	cfg.ApplyDefaults()
	srv, adminToken, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	base := "http://" + ln.Addr().String()
	srv.SetBaseURL(base)
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	step("📤 AgentTransfer demo — everything below runs on %s with zero config\n", base)

	// 1. Two agents.
	alice, aliceKey, err := demoCreateAgent(base, adminToken, "alice")
	if err != nil {
		return err
	}
	bob, bobKey, err := demoCreateAgent(base, adminToken, "bob")
	if err != nil {
		return err
	}
	step("✓ created agents %s and %s (each has an email address + API key)", alice, bob)

	// 2. Alice uploads 1 MiB of random bytes.
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	wantSHA := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantSHA[:])

	req, _ := http.NewRequest("PUT", base+"/v1/files/dataset.bin", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+aliceKey)
	var up struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := demoDo(req, &up); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	if up.SHA256 != wantHex {
		return fmt.Errorf("upload hash mismatch: %s != %s", up.SHA256, wantHex)
	}
	step("✓ alice uploaded dataset.bin (%d bytes) — content-addressed as sha256:%s…", up.Size, up.SHA256[:12])

	// 3. Alice sends it to bob (same-instance: lands straight in his inbox).
	sendBody, _ := json.Marshal(map[string]any{
		"to":   []string{bob},
		"file": "sha256:" + up.SHA256,
		"note": "training set v3 — hash-verify before use",
		"ttl":  "1h",
	})
	req, _ = http.NewRequest("POST", base+"/v1/send", bytes.NewReader(sendBody))
	req.Header.Set("Authorization", "Bearer "+aliceKey)
	req.Header.Set("Idempotency-Key", "demo-send-1")
	var sent struct {
		MessageID string `json:"message_id"`
		Link      struct {
			URL       string `json:"url"`
			ExpiresAt string `json:"expires_at"`
		} `json:"link"`
	}
	if err := demoDo(req, &sent); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	step("✓ alice → bob: message %s with an ephemeral link (expires %s)", sent.MessageID, sent.Link.ExpiresAt)

	// 4. Bob long-polls his inbox.
	req, _ = http.NewRequest("GET", base+"/v1/inbox/wait?timeout=10", nil)
	req.Header.Set("Authorization", "Bearer "+bobKey)
	var inbox struct {
		Messages []struct {
			ID      string `json:"id"`
			From    string `json:"from"`
			Subject string `json:"subject"`
			Offer   struct {
				URL     string `json:"url"`
				SHA256  string `json:"sha256"`
				Size    int64  `json:"size"`
				Trusted bool   `json:"trusted"`
			} `json:"offer"`
		} `json:"messages"`
	}
	if err := demoDo(req, &inbox); err != nil {
		return fmt.Errorf("inbox: %w", err)
	}
	if len(inbox.Messages) == 0 {
		return fmt.Errorf("bob's inbox is empty — delivery failed")
	}
	m := inbox.Messages[0]
	step("✓ bob long-polled his inbox and got the offer from %s (provenance: trusted=%v)", m.From, m.Offer.Trusted)

	// 5. Bob downloads and verifies.
	req, _ = http.NewRequest("GET", m.Offer.URL+"?dl=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	gotHex := hex.EncodeToString(h.Sum(nil))
	if gotHex != m.Offer.SHA256 || gotHex != wantHex {
		return fmt.Errorf("HASH MISMATCH: got %s want %s", gotHex, m.Offer.SHA256)
	}
	step("✓ bob downloaded %d bytes over HTTPS and the sha256 matches the offer — integrity proven", n)

	// 6. Mark read.
	req, _ = http.NewRequest("POST", base+"/v1/inbox/"+m.ID+"/read", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+bobKey)
	_ = demoDo(req, nil)

	// 7. Verify the signed receipt chain (the full instance export).
	req, _ = http.NewRequest("GET", base+"/.well-known/agenttransfer", nil)
	var wk struct {
		ReceiptPubkey string `json:"receipt_pubkey"`
	}
	if err := demoDo(req, &wk); err != nil {
		return err
	}
	pub, err := receipt.ParsePublicKey(wk.ReceiptPubkey)
	if err != nil {
		return err
	}
	req, _ = http.NewRequest("GET", base+"/v1/receipts/export", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	rs, err := receipt.ReadJSONL(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	// The export is already in chain order — verify it as-is.
	if err := receipt.VerifyChain(rs, pub, true); err != nil {
		return fmt.Errorf("receipt chain verification failed: %w", err)
	}
	step("✓ receipt chain verified: %d signed receipts, no gaps, no tampering", len(rs))
	for _, r := range rs {
		step("    %s", formatReceiptLine(r))
	}

	step("\nThat's the whole loop: upload → send → long-poll → download → hash match → signed evidence.")
	step("Next: `agenttransfer serve` on a VPS with DOMAIN + OUTBOUND set makes this work across the internet, over real email.")
	return nil
}

func demoCreateAgent(base, adminToken, name string) (email, key string, err error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, _ := http.NewRequest("POST", base+"/v1/agents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	var out struct {
		Email  string `json:"email"`
		APIKey string `json:"api_key"`
	}
	if err := demoDo(req, &out); err != nil {
		return "", "", fmt.Errorf("create %s: %w", name, err)
	}
	return out.Email, out.APIKey, nil
}

func demoDo(req *http.Request, out any) error {
	if req.Body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
