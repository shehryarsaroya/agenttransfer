package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

func cloneMCPArgs(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func TestHostedMCPSendSchemaRequiresIdempotencyKey(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("mcp-idem-schema")
	listed := hostedMCPRPC(t, e, key, "tools/list", map[string]any{})
	tools, _ := listed["tools"].([]any)
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		if tool["name"] != "send" {
			continue
		}
		schema, _ := tool["inputSchema"].(map[string]any)
		required, _ := schema["required"].([]any)
		for _, field := range required {
			if field == "idempotency_key" {
				return
			}
		}
		t.Fatalf("send required fields = %v", required)
	}
	t.Fatal("hosted tools/list omitted send")
}

func TestHostedMCPInlineLinkHonorsInFlightSevering(t *testing.T) {
	e := newEnv(t)
	senderEmail, senderKey := e.createAgent("mcp-sever-sender")
	_, downloaderKey := e.createAgent("mcp-sever-downloader")
	uploaded := e.upload(senderKey, "secret.txt", []byte("must not escape after revoke"), "?share=1")
	link := uploaded["link"].(map[string]any)
	token := link["token"].(string)

	// sever is set after a revoke/delete commits. Keep the row active here to
	// deterministically model the narrow lookup/read race inside the MCP call.
	e.srv.sever(token)
	text, failed := hostedMCPTool(t, e, downloaderKey, "download_file", map[string]any{"url": link["url"]})
	if !failed || !strings.Contains(text, "revoked") {
		t.Fatalf("severed inline download failed=%v text=%q", failed, text)
	}
	stored, err := e.srv.st.GetLink(token)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Downloads != 0 {
		t.Fatalf("severed inline download was counted: %d", stored.Downloads)
	}
	receipts, err := e.srv.st.ListReceipts(senderEmail, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range receipts {
		if got.Action == receipt.ActionDownloaded && got.Target == "link:"+token {
			t.Fatalf("severed inline download emitted receipt: %+v", got)
		}
	}
}

func TestHostedMCPSendRequiresVisibleASCIIIdempotencyKey(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("mcp-idem-key")
	_, _ = e.createAgent("mcp-idem-target")
	base := map[string]any{"to": []string{"mcp-idem-target@local"}, "note": "hello"}
	tests := []struct {
		name string
		key  any
	}{
		{name: "missing", key: nil},
		{name: "empty", key: ""},
		{name: "space", key: "not visible"},
		{name: "control", key: "bad\nkey"},
		{name: "non-ascii", key: "café"},
		{name: "too-long", key: strings.Repeat("x", store.MaxIdempotencyKeyBytes+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := cloneMCPArgs(base)
			if tt.key != nil {
				args["idempotency_key"] = tt.key
			}
			text, failed := hostedMCPTool(t, e, key, "send", args)
			if !failed || !strings.Contains(text, "idempotency_key") {
				t.Fatalf("send failed=%v text=%q", failed, text)
			}
		})
	}
}

func TestHostedMCPSendReplaysExactResultAndBindsCompleteRequest(t *testing.T) {
	e := newEnv(t)
	_, senderKey := e.createAgent("mcp-idem-sender")
	bobEmail, bobKey := e.createAgent("mcp-idem-bob")
	base := map[string]any{
		"to": []string{bobEmail}, "note": "hello", "subject": "subject",
		"idempotency_key": "mcp-stable-send",
	}
	first, failed := hostedMCPTool(t, e, senderKey, "send", base)
	if failed {
		t.Fatalf("first send failed: %s", first)
	}
	// Normalization is part of the fingerprint: case/whitespace-only changes
	// replay the exact original tool result rather than creating another send.
	equivalent := cloneMCPArgs(base)
	equivalent["to"] = []string{"  " + strings.ToUpper(bobEmail) + "  "}
	equivalent["note"] = "  hello  "
	equivalent["subject"] = " subject "
	replayed, failed := hostedMCPTool(t, e, senderKey, "send", equivalent)
	if failed || replayed != first {
		t.Fatalf("replay failed=%v\nfirst=%s\nreplay=%s", failed, first, replayed)
	}
	// MCP and REST deliberately share the durable response shape. Crossing
	// transports with the same normalized request must replay, not deliver.
	restBody, _ := json.Marshal(map[string]any{
		"to": []string{bobEmail}, "note": "hello", "subject": "subject",
	})
	restResp, restRaw := e.do(http.MethodPost, "/v1/send", senderKey, bytes.NewReader(restBody), "application/json",
		"Idempotency-Key", "mcp-stable-send")
	if restResp.StatusCode != http.StatusCreated || restResp.Header.Get("Idempotent-Replay") != "true" {
		t.Fatalf("cross-transport replay: HTTP %d replay=%q body=%s",
			restResp.StatusCode, restResp.Header.Get("Idempotent-Replay"), restRaw)
	}
	var firstResult, restResult map[string]any
	if json.Unmarshal([]byte(first), &firstResult) != nil || json.Unmarshal(restRaw, &restResult) != nil || !reflect.DeepEqual(firstResult, restResult) {
		t.Fatalf("cross-transport result mismatch:\nMCP  %s\nREST %s", first, restRaw)
	}
	var inbox struct {
		Messages []map[string]any `json:"messages"`
	}
	if code := e.doJSON(http.MethodGet, "/v1/inbox", bobKey, nil, &inbox); code != http.StatusOK || len(inbox.Messages) != 1 {
		t.Fatalf("replayed send delivered %d messages (HTTP %d), want 1", len(inbox.Messages), code)
	}

	mutations := map[string]func(map[string]any){
		"to":       func(v map[string]any) { v["to"] = []string{"other@local"} },
		"file":     func(v map[string]any) { v["file"] = "different.bin" },
		"note":     func(v map[string]any) { v["note"] = "different" },
		"subject":  func(v map[string]any) { v["subject"] = "different" },
		"ttl":      func(v map[string]any) { v["ttl"] = "2h" },
		"once":     func(v map[string]any) { v["once"] = true },
		"reply_to": func(v map[string]any) { v["reply_to"] = "msg_different" },
		"cc_owner": func(v map[string]any) { v["cc_owner"] = true },
		"enc_mode": func(v map[string]any) { v["enc_mode"] = "sealed" },
	}
	for name, mutate := range mutations {
		t.Run("conflict-"+name, func(t *testing.T) {
			changed := cloneMCPArgs(base)
			mutate(changed)
			text, failed := hostedMCPTool(t, e, senderKey, "send", changed)
			if !failed || !strings.Contains(text, "bound to a different send request") {
				t.Fatalf("changed %s failed=%v text=%q", name, failed, text)
			}
		})
	}
}

func TestHostedMCPSendReplaysTerminalFailureAndRejectsPending(t *testing.T) {
	e := newEnv(t)
	_, senderKey := e.createAgent("mcp-idem-failure")
	failureArgs := map[string]any{
		"to": []string{"appears-later@local"}, "note": "hello",
		"idempotency_key": "mcp-terminal-failure",
	}
	first, failed := hostedMCPTool(t, e, senderKey, "send", failureArgs)
	if !failed {
		t.Fatalf("missing recipient unexpectedly succeeded: %s", first)
	}
	_, laterKey := e.createAgent("appears-later")
	replayed, failed := hostedMCPTool(t, e, senderKey, "send", failureArgs)
	if !failed || replayed != first {
		t.Fatalf("terminal failure replay failed=%v first=%q replay=%q", failed, first, replayed)
	}
	var laterInbox struct {
		Messages []map[string]any `json:"messages"`
	}
	if code := e.doJSON(http.MethodGet, "/v1/inbox", laterKey, nil, &laterInbox); code != http.StatusOK || len(laterInbox.Messages) != 0 {
		t.Fatalf("terminal failure was re-executed: HTTP %d inbox=%v", code, laterInbox.Messages)
	}

	agent, err := e.srv.st.AgentByKey(senderKey)
	if err != nil {
		t.Fatal(err)
	}
	pendingReq := normalizeSendRequest(sendRequest{To: []string{"appears-later@local"}, Note: "pending"})
	pendingHash, err := sendRequestHash(pendingReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := e.srv.st.BeginIdempotent(agent.ID, "mcp-pending", pendingHash); err != nil || !created {
		t.Fatalf("seed pending reservation: created=%v err=%v", created, err)
	}
	pendingText, failed := hostedMCPTool(t, e, senderKey, "send", map[string]any{
		"to": []string{"appears-later@local"}, "note": "pending", "idempotency_key": "mcp-pending",
	})
	if !failed || !strings.Contains(pendingText, "unfinished prior request") {
		t.Fatalf("pending send failed=%v text=%q", failed, pendingText)
	}
}

func TestHostedMCPWhoamiMatchesRESTIdentityAndHostingProjection(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("mcp-whoami")
	humanVerifyAgent(t, e, key, "owner@example.test")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetPublicContact(agent.ID, "public@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetPubkey(agent.ID, testRecipient(t)); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetPolicy(agent.ID, "known", []string{"friend@example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.st.EnsureApp(agent.ID, agent.Name); err != nil {
		t.Fatal(err)
	}

	var rest map[string]any
	if code := e.doJSON(http.MethodGet, "/v1/whoami", key, nil, &rest); code != http.StatusOK {
		t.Fatalf("REST whoami HTTP %d", code)
	}
	text, failed := hostedMCPTool(t, e, key, "whoami", map[string]any{})
	if failed {
		t.Fatalf("MCP whoami failed: %s", text)
	}
	var mcp map[string]any
	if err := json.Unmarshal([]byte(text), &mcp); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"agent_id", "name", "email", "owner_email", "owner_verified", "instance",
		"pubkey", "sealed_enabled", "accept_policy", "verified", "public_contact",
		"storage", "limits", "remote_recipients", "email_enabled", "hosting",
	} {
		if !reflect.DeepEqual(mcp[field], rest[field]) {
			t.Errorf("field %s:\nMCP  %#v\nREST %#v", field, mcp[field], rest[field])
		}
	}
	if strings.Contains(text, key) {
		t.Fatal("MCP whoami leaked the bearer key")
	}
}

func TestHostedMCPAppStatusIsReadOnlyWhenNoAppExists(t *testing.T) {
	e := newAppTestEnv(t, 4<<20)
	_, key := e.createAgent("mcp-readonly-status")
	humanVerifyAgent(t, e, key, "owner@example.test")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	text, failed := hostedMCPTool(t, e, key, "app_status", map[string]any{})
	if failed {
		t.Fatalf("app_status failed: %s", text)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(text), &status); err != nil {
		t.Fatal(err)
	}
	if status["eligible"] != true || status["app"] != nil || status["domain"] != testAppDomain {
		t.Fatalf("absent app projection = %#v", status)
	}
	var rest map[string]any
	if code := e.doJSON(http.MethodGet, "/v1/apps/self", key, nil, &rest); code != http.StatusOK || !reflect.DeepEqual(status, rest) {
		t.Fatalf("app_status parity: HTTP %d\nMCP  %#v\nREST %#v", code, status, rest)
	}
	if _, err := e.srv.st.AppByAgentID(agent.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("app_status created state: %v", err)
	}
}

func TestHostedMCPRejectsBodyBeyondLimitAndUsesHonestInstructions(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("mcp-framing")
	base, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-06-18"},
	})
	oversized := append(base, bytes.Repeat([]byte(" "), maxMCPRequestBytes+1-len(base))...)
	resp, body := e.do(http.MethodPost, "/mcp", key, bytes.NewReader(oversized), "application/json")
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !bytes.Contains(body, []byte("exceeds 4 MiB")) {
		t.Fatalf("oversized MCP request: HTTP %d body=%s", resp.StatusCode, body)
	}

	initialized := hostedMCPRPC(t, e, key, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	instructions, _ := initialized["instructions"].(string)
	if !strings.Contains(instructions, "best-effort signed receipts") || strings.Contains(instructions, "Every action") {
		t.Fatalf("initialize instructions = %q", instructions)
	}
}

func TestHostedMCPNegotiatesSupportedProtocolVersions(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("mcp-version")
	tests := []struct {
		name      string
		requested string
		want      string
	}{
		{name: "latest", requested: latestMCPProtocolVersion, want: latestMCPProtocolVersion},
		{name: "previous", requested: previousMCPProtocolVersion, want: previousMCPProtocolVersion},
		{name: "older unsupported", requested: "2025-03-26", want: latestMCPProtocolVersion},
		{name: "future unsupported", requested: "2099-01-01", want: latestMCPProtocolVersion},
		{name: "missing", want: latestMCPProtocolVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]any{}
			if tt.requested != "" {
				params["protocolVersion"] = tt.requested
			}
			result := hostedMCPRPC(t, e, key, "initialize", params)
			if result["protocolVersion"] != tt.want {
				t.Fatalf("protocolVersion = %v, want %q", result["protocolVersion"], tt.want)
			}
		})
	}
}

func TestHostedMCPValidatesOriginAgainstCurrentBaseURL(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("mcp-origin")
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "ping", "params": map[string]any{},
	})
	tests := []struct {
		name   string
		origin string
		want   int
	}{
		{name: "omitted", want: http.StatusOK},
		{name: "same origin", origin: e.srv.BaseURL(), want: http.StatusOK},
		{name: "cross origin", origin: "https://attacker.example", want: http.StatusForbidden},
		{name: "opaque null origin", origin: "null", want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := []string(nil)
			if tt.origin != "" {
				headers = []string{"Origin", tt.origin}
			}
			resp, got := e.do(http.MethodPost, "/mcp", key, bytes.NewReader(body), "application/json", headers...)
			if resp.StatusCode != tt.want {
				t.Fatalf("HTTP %d, want %d: %s", resp.StatusCode, tt.want, got)
			}
		})
	}
}
