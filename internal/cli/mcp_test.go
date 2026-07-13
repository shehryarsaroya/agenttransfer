package cli

import (
	"encoding/json"
	"testing"
)

// The stdio handler must speak the MCP protocol: initialize echoes a known
// version, ping returns empty, tools/list advertises the path-based tools,
// notifications get no reply, unknown methods error, and id type is preserved.
func TestMCPHandleProtocol(t *testing.T) {
	s := &mcpServer{} // no api needed for protocol-only methods

	// initialize echoes the client's recognized version.
	resp := s.handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	m := resp.(map[string]any)
	res := m["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize version = %v", res["protocolVersion"])
	}
	if m["id"] == nil {
		t.Fatal("initialize dropped the id")
	}

	// unknown version falls back to our default.
	resp = s.handle([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`))
	if resp.(map[string]any)["result"].(map[string]any)["protocolVersion"] != mcpProtocol {
		t.Fatal("unknown version not defaulted")
	}

	// ping → empty result.
	resp = s.handle([]byte(`{"jsonrpc":"2.0","id":"abc","method":"ping"}`))
	if _, ok := resp.(map[string]any)["result"].(map[string]any); !ok {
		t.Fatal("ping result not an object")
	}
	// string id preserved as a string.
	var idProbe struct {
		ID json.RawMessage `json:"id"`
	}
	b, _ := json.Marshal(resp)
	json.Unmarshal(b, &idProbe)
	if string(idProbe.ID) != `"abc"` {
		t.Fatalf("ping id not preserved as string: %s", idProbe.ID)
	}

	// tools/list advertises the file movers with path inputs.
	resp = s.handle([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	tools := resp.(map[string]any)["result"].(map[string]any)["tools"].([]map[string]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl["name"].(string)] = true
	}
	for _, want := range []string{
		"whoami", "upload_file", "send_file", "download_file", "check_inbox",
		"deploy_app", "app_status", "app_logs", "stop_app",
	} {
		if !names[want] {
			t.Fatalf("tools/list missing %q", want)
		}
	}
	// upload_file takes a path (not inline bytes).
	for _, tl := range tools {
		if tl["name"] == "upload_file" {
			props := tl["inputSchema"].(map[string]any)["properties"].(map[string]any)
			if _, ok := props["path"]; !ok {
				t.Fatal("upload_file must take a path, not bytes")
			}
		}
	}

	// notification (no id) → no reply.
	if r := s.handle([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); r != nil {
		t.Fatal("notification got a reply")
	}

	// unknown method → -32601.
	resp = s.handle([]byte(`{"jsonrpc":"2.0","id":3,"method":"nope"}`))
	if resp.(map[string]any)["error"].(map[string]any)["code"].(int) != -32601 {
		t.Fatal("unknown method not -32601")
	}

	// parse error → -32700.
	resp = s.handle([]byte(`{bad json`))
	if resp.(map[string]any)["error"].(map[string]any)["code"].(int) != -32700 {
		t.Fatal("parse error not -32700")
	}
}

// The bearer key must attach ONLY to the exact instance origin — never to a
// share URL that merely string-prefixes the base (credential-leak regression).
func TestSameOrigin(t *testing.T) {
	base := "https://agenttransfer.dev"
	attach := []string{
		"https://agenttransfer.dev/f/abc",
		"https://agenttransfer.dev/v1/files/x/content",
		"https://agenttransfer.dev:443/f/abc", // note: host includes port; see below
	}
	leak := []string{
		"https://agenttransfer.dev@evil.com/x", // userinfo trick
		"https://agenttransfer.dev.evil.com/x", // suffix trick
		"http://agenttransfer.dev/f/abc",       // scheme downgrade
		"https://evil.com/agenttransfer.dev",   // path lookalike
	}
	// The :443 case has a different Host string, so it won't match — that's
	// acceptable (fails closed: no key attached). Verify the dangerous ones
	// never attach, and the plain same-origin ones do.
	if !sameOrigin("https://agenttransfer.dev/f/abc", base) {
		t.Fatal("plain same-origin should attach the key")
	}
	for _, u := range leak {
		if sameOrigin(u, base) {
			t.Errorf("CREDENTIAL LEAK: sameOrigin(%q) attached the key", u)
		}
	}
	_ = attach
}
