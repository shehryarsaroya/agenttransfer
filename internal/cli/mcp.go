package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

// cmdMCP runs a local Model Context Protocol server over stdio, bridging an AI
// agent's MCP client to this instance's REST API. Its reason to exist: the
// file-moving tools take local filesystem PATHS and stream to/from disk, so a
// 5 GB transfer never enters the model's context window — the tool result is
// just a one-line summary (url/path, size, sha256). It also encrypts/decrypts
// client-side, so sealed and --encrypt transfers work through MCP too.
//
// Credentials come from the environment (AGENTTRANSFER_URL / _KEY /
// _IDENTITY), which is exactly how MCP clients launch a stdio server — e.g.
//
//	{"mcpServers":{"agenttransfer":{"command":"agenttransfer","args":["mcp"],
//	  "env":{"AGENTTRANSFER_URL":"https://agents.example.com","AGENTTRANSFER_KEY":"at_live_…"}}}}
func cmdMCP(_ []string) error {
	log.SetOutput(os.Stderr) // stdout is protocol-only; all diagnostics to stderr
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	a := newAPI(cfg)

	in := bufio.NewReaderSize(os.Stdin, 1<<20) // ReadBytes grows past this; not bufio.Scanner (64K cap)
	var wmu sync.Mutex
	writeMsg := func(v any) {
		b, _ := json.Marshal(v) // compact — MCP forbids embedded newlines
		wmu.Lock()
		os.Stdout.Write(append(b, '\n'))
		wmu.Unlock()
	}

	srv := &mcpServer{a: a, cfg: cfg}
	for {
		line, rerr := in.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 { // skip blank/keepalive lines
			if resp := srv.safeHandle(line); resp != nil {
				writeMsg(resp)
			}
		}
		if rerr != nil {
			return nil // EOF: stdin closed → client is shutting us down
		}
	}
}

const mcpProtocol = "2025-11-25"

type mcpServer struct {
	a   *api
	cfg clientConfig
}

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // preserve string|number|absent
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func rpcResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result}
}
func rpcError(id json.RawMessage, code int, msg string) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": msg}}
	if len(id) > 0 {
		m["id"] = json.RawMessage(id)
	} else {
		m["id"] = nil
	}
	return m
}

// safeHandle wraps handle with panic recovery so one bad tool call becomes an
// isError result instead of unwinding through the read loop and killing the
// whole stdio session.
func (s *mcpServer) safeHandle(line []byte) (resp any) {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(line, &probe)
	defer func() {
		if r := recover(); r != nil {
			if len(probe.ID) == 0 {
				resp = nil // panic while handling a notification: no reply
				return
			}
			resp = rpcResult(probe.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("internal error: %v", r)}},
				"isError": true,
			})
		}
	}()
	return s.handle(line)
}

// handle dispatches one JSON-RPC line; returns the response to write, or nil
// for notifications (which get no reply).
func (s *mcpServer) handle(line []byte) any {
	var m rpcMsg
	if err := json.Unmarshal(line, &m); err != nil {
		return rpcError(nil, -32700, "parse error")
	}
	if len(m.ID) == 0 { // notification (e.g. notifications/initialized) — never reply
		return nil
	}
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		ver := mcpProtocol
		if p.ProtocolVersion == "2025-06-18" || p.ProtocolVersion == "2025-11-25" {
			ver = p.ProtocolVersion // echo a version we recognize
		}
		return rpcResult(m.ID, map[string]any{
			"protocolVersion": ver,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agenttransfer", "version": "mcp-bridge"},
			"instructions": "AgentTransfer file transfer. upload_file/send_file/download_file take LOCAL PATHS " +
				"and stream — safe for multi-GB files (bytes never enter your context). Set encrypt/seal to " +
				"encrypt client-side.",
		})
	case "ping":
		return rpcResult(m.ID, map[string]any{})
	case "tools/list":
		return rpcResult(m.ID, map[string]any{"tools": mcpProxyTools})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			return rpcError(m.ID, -32602, "invalid params")
		}
		text, err := s.call(p.Name, p.Arguments)
		if err != nil {
			// Tool ran and failed → isError result (the model sees + reacts).
			return rpcResult(m.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			})
		}
		return rpcResult(m.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		})
	default:
		return rpcError(m.ID, -32601, "method not found: "+m.Method)
	}
}

func mstr(desc string) map[string]any  { return map[string]any{"type": "string", "description": desc} }
func mbool(desc string) map[string]any { return map[string]any{"type": "boolean", "description": desc} }
func mint(desc string) map[string]any  { return map[string]any{"type": "integer", "description": desc} }
func mobj(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

var mcpProxyTools = []map[string]any{
	{"name": "whoami", "description": "Your agent identity, storage usage/quota, and sealed-transfer status.", "inputSchema": mobj(map[string]any{})},
	{"name": "list_files", "description": "List the files in your folder.", "inputSchema": mobj(map[string]any{})},
	{
		"name": "upload_file",
		"description": "Stream a LOCAL file into your folder (any size — bytes never enter your context). " +
			"Optionally mint a share link and/or encrypt client-side.",
		"inputSchema": mobj(map[string]any{
			"path":    mstr("absolute local path to upload"),
			"share":   mbool("also mint a share link"),
			"ttl":     mstr("share link TTL like \"3h\" (max 24h)"),
			"once":    mbool("burn-after-read link"),
			"encrypt": mbool("encrypt locally with a symmetric key (returned in the result)"),
		}, "path"),
	},
	{
		"name": "send_file",
		"description": "Send a local file and/or a note to agents or humans. Same-instance agents get instant " +
			"inbox delivery; others get email with a download link. encrypt = symmetric key (returned); " +
			"seal = encrypt to the recipients' keys (same-instance).",
		"inputSchema": mobj(map[string]any{
			"to":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "recipient addresses"},
			"path":            mstr("optional local file to attach"),
			"note":            mstr("message text"),
			"subject":         mstr("optional subject"),
			"ttl":             mstr("link TTL like \"3h\""),
			"once":            mbool("burn-after-read link"),
			"cc_owner":        mbool("CC your human owner"),
			"encrypt":         mbool("symmetric encryption (key returned to share out-of-band)"),
			"seal":            mbool("seal to recipients' keys (same-instance only; changed keys are refused)"),
			"repin":           mbool("accept changed recipient keys only after independent verification"),
			"idempotency_key": mstr("stable retry key; a later tool retry works for a note or unchanged plaintext, while encrypted paths require exact REST replay of the uploaded ciphertext reference"),
		}, "to"),
	},
	{
		"name": "download_file",
		"description": "Stream a file to a LOCAL path (any size — bytes never enter your context), verifying " +
			"its sha256. Accepts an inbox message id (msg_...), a share URL, or a sha256 from your folder. " +
			"Decrypts automatically for sealed offers; pass key for symmetric ones.",
		"inputSchema": mobj(map[string]any{
			"ref":      mstr("msg_... | share URL | sha256:... | 64-hex"),
			"out_path": mstr("absolute local path to write"),
			"key":      mstr("symmetric decryption key (atk_...), if the file was --encrypt'd"),
			"seal":     mbool("decrypt with your own identity (needed for a sealed file fetched by URL/sha256, not a msg_ offer)"),
		}, "ref", "out_path"),
	},
	{"name": "check_inbox", "description": "List inbox messages; set wait_seconds to long-poll.", "inputSchema": mobj(map[string]any{
		"unread":       mbool("only unread (default true)"),
		"wait_seconds": mint("long-poll up to this many seconds (max 60)"),
	})},
	{"name": "read_message", "description": "Fetch one inbox message by id and mark it read.", "inputSchema": mobj(map[string]any{"id": mstr("msg_...")}, "id")},
	{"name": "create_upload_request", "description": "Mint a one-time browser upload page a human can drop a file into.", "inputSchema": mobj(map[string]any{
		"note": mstr("what you want uploaded"), "ttl": mstr("page lifetime like \"24h\""),
	})},
	{"name": "get_receipts", "description": "Your signed receipt trail.", "inputSchema": mobj(map[string]any{"limit": mint("max receipts")})},

	// Agent-first coordination: discovery (find_agents/set_card) and shared
	// spaces (list/create/add-member/post/read/get-file). Spaces are same-
	// instance. The file tools keep the bridge's path discipline — post_to_space
	// streams a LOCAL path in and offers it by sha256; get_space_file streams out.
	{"name": "find_agents", "description": "Discover agents on this instance that opted into the directory; filter by a capability tag. Returns each agent's name, description, and capabilities.", "inputSchema": mobj(map[string]any{
		"capability": mstr("only agents advertising this capability tag"),
		"limit":      mint("max agents to return"),
	})},
	{
		"name": "set_card",
		"description": "Publish or update your own discovery card so other agents can find you. listed=true opts you " +
			"into the directory. Replaces the whole card, so pass the full set of capabilities each time.",
		"inputSchema": mobj(map[string]any{
			"description":  mstr("what you are and what you do"),
			"capabilities": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "capability tags others can search for"},
			"listed":       mbool("appear in the public directory (default false)"),
		}, "description"),
	},
	{"name": "list_spaces", "description": "List the shared spaces you belong to.", "inputSchema": mobj(map[string]any{})},
	{"name": "create_space", "description": "Open a new shared space (you become its owner). Returns the new space id.", "inputSchema": mobj(map[string]any{
		"name": mstr("human-readable space name"),
	}, "name")},
	{"name": "add_space_member", "description": "Add a local agent to a space you own (membership grants read access to its whole history).", "inputSchema": mobj(map[string]any{
		"space_id": mstr("space id (spc_...)"),
		"agent":    mstr("agent to add (\"name\" or \"name@instance\")"),
	}, "space_id", "agent")},
	{
		"name": "post_to_space",
		"description": "Post to a space's shared stream: a message, a file, or both. file is a LOCAL PATH — it is " +
			"streamed into your folder (bytes never enter your context) and offered to the space by sha256.",
		"inputSchema": mobj(map[string]any{
			"space_id": mstr("space id (spc_...)"),
			"text":     mstr("message text, or a caption for the file"),
			"file":     mstr("optional absolute local path to attach"),
		}, "space_id"),
	},
	{
		"name": "read_space",
		"description": "Read a space's shared stream after a cursor; set wait_seconds to long-poll for new events. " +
			"Returns the events plus a new cursor — pass it back as since to poll incrementally.",
		"inputSchema": mobj(map[string]any{
			"space_id":     mstr("space id (spc_...)"),
			"since":        mint("only events after this cursor (0 = from the start)"),
			"wait_seconds": mint("long-poll up to this many seconds (max 60)"),
		}, "space_id"),
	},
	{
		"name": "get_space_file",
		"description": "Stream a file shared in a space to a LOCAL path (any size — bytes never enter your context), " +
			"verifying its sha256.",
		"inputSchema": mobj(map[string]any{
			"space_id": mstr("space id (spc_...)"),
			"sha256":   mstr("sha256 of the file (from a file event in the space)"),
			"out_path": mstr("absolute local path to write"),
		}, "space_id", "sha256", "out_path"),
	},
	{
		"name":        "deploy_app",
		"description": "Deploy a website/app for this verified agent. Provide either path (a LOCAL directory or archive, streamed without entering context) or an OCI image. Directory deployments are safely packaged and omit .git.",
		"inputSchema": mobj(map[string]any{
			"path":        mstr("local directory or archive to deploy"),
			"image":       mstr("OCI image to deploy instead of local source"),
			"kind":        mstr("static or container; inferred when omitted"),
			"port":        mint("container HTTP port (default 8080)"),
			"env":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "container environment variables"},
			"command":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "container argv override"},
			"spa":         mbool("serve index.html for unknown static-site routes"),
			"health_path": mstr("container path that must return 2xx before activation (default /)"),
		}),
	},
	{"name": "app_status", "description": "Get this agent's app status, URL, and active deployment.", "inputSchema": mobj(map[string]any{})},
	{"name": "app_logs", "description": "Read a bounded tail of this agent's app logs.", "inputSchema": mobj(map[string]any{
		"tail": mint("number of recent lines, 1-2000 (default 200)"),
	})},
	{"name": "stop_app", "description": "Stop this agent's currently running app without deleting its configuration or persistent data.", "inputSchema": mobj(map[string]any{})},
}

// call runs one tool and returns a short text summary (never file bytes).
func (s *mcpServer) call(name string, args json.RawMessage) (string, error) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch name {
	case "whoami":
		return s.passthrough("GET", "/v1/whoami", nil)
	case "list_files":
		return s.passthrough("GET", "/v1/files", nil)

	case "upload_file":
		var p struct {
			Path                 string `json:"path"`
			Share, Once, Encrypt bool
			TTL                  string `json:"ttl"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.Path == "" {
			return "", fmt.Errorf("path is required")
		}
		sha, size, link, key, err := s.upload(p.Path, p.Share || p.TTL != "" || p.Once, p.TTL, p.Once, p.Encrypt, nil)
		if err != nil {
			return "", err
		}
		msg := fmt.Sprintf("Uploaded %s (%d bytes, sha256:%s)", filepath.Base(p.Path), size, sha)
		if p.Encrypt {
			msg = fmt.Sprintf("Uploaded %s encrypted (sha256:%s ciphertext). Symmetric key to share out-of-band: %s", filepath.Base(p.Path), sha, key)
		}
		if link != "" {
			msg += "\nLink: " + link
		}
		return msg, nil

	case "send_file":
		return s.sendFile(args)

	case "download_file":
		var p struct {
			Ref     string `json:"ref"`
			OutPath string `json:"out_path"`
			Key     string `json:"key"`
			Seal    bool   `json:"seal"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.Ref == "" || p.OutPath == "" {
			return "", fmt.Errorf("ref and out_path are required")
		}
		return s.download(p.Ref, p.OutPath, p.Key, p.Seal)

	case "check_inbox":
		var p struct {
			Unread      *bool `json:"unread"`
			WaitSeconds int   `json:"wait_seconds"`
		}
		_ = json.Unmarshal(args, &p)
		unread := "1"
		if p.Unread != nil && !*p.Unread {
			unread = "0"
		}
		path := "/v1/inbox?unread=" + unread
		if p.WaitSeconds > 0 {
			if p.WaitSeconds > 60 {
				p.WaitSeconds = 60
			}
			path = fmt.Sprintf("/v1/inbox/wait?timeout=%d", p.WaitSeconds)
		}
		return s.passthrough("GET", path, nil)

	case "read_message":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(args, &p); err != nil || p.ID == "" {
			return "", fmt.Errorf("id is required")
		}
		out, err := s.passthrough("GET", "/v1/inbox/"+url.PathEscape(p.ID), nil)
		if err != nil {
			return "", err
		}
		_ = s.a.json("POST", "/v1/inbox/"+url.PathEscape(p.ID)+"/read", map[string]any{}, nil)
		return out, nil

	case "create_upload_request":
		var p struct {
			Note string `json:"note"`
			TTL  string `json:"ttl"`
		}
		_ = json.Unmarshal(args, &p)
		body := map[string]any{"note": p.Note}
		if p.TTL != "" {
			body["ttl"] = p.TTL
		}
		return s.passthrough("POST", "/v1/requests", body)

	case "get_receipts":
		var p struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(args, &p)
		path := "/v1/receipts"
		if p.Limit > 0 {
			path += fmt.Sprintf("?limit=%d", p.Limit)
		}
		return s.passthrough("GET", path, nil)

	case "find_agents":
		var p struct {
			Capability string `json:"capability"`
			Limit      int    `json:"limit"`
		}
		_ = json.Unmarshal(args, &p)
		q := url.Values{}
		if p.Capability != "" {
			q.Set("capability", p.Capability)
		}
		if p.Limit > 0 {
			q.Set("limit", fmt.Sprintf("%d", p.Limit))
		}
		path := "/v1/directory"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return s.passthrough("GET", path, nil)

	case "set_card":
		var p struct {
			Description  string   `json:"description"`
			Capabilities []string `json:"capabilities"`
			Listed       *bool    `json:"listed"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if strings.TrimSpace(p.Description) == "" {
			return "", fmt.Errorf("description is required")
		}
		body := map[string]any{"description": p.Description}
		if p.Capabilities != nil {
			body["capabilities"] = p.Capabilities
		}
		if p.Listed != nil {
			body["listed"] = *p.Listed
		}
		return s.passthrough("PUT", "/v1/agents/self/card", body)

	case "list_spaces":
		return s.passthrough("GET", "/v1/spaces", nil)

	case "create_space":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if strings.TrimSpace(p.Name) == "" {
			return "", fmt.Errorf("name is required")
		}
		var out struct {
			Space struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"space"`
		}
		if err := s.a.json("POST", "/v1/spaces", map[string]any{"name": p.Name}, &out); err != nil {
			return "", err
		}
		return fmt.Sprintf("Created space %q (id: %s)", out.Space.Name, out.Space.ID), nil

	case "add_space_member":
		var p struct {
			SpaceID string `json:"space_id"`
			Agent   string `json:"agent"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.SpaceID == "" || p.Agent == "" {
			return "", fmt.Errorf("space_id and agent are required")
		}
		return s.passthrough("POST", "/v1/spaces/"+url.PathEscape(p.SpaceID)+"/members", map[string]any{"agent": p.Agent})

	case "post_to_space":
		return s.postToSpace(args)

	case "read_space":
		var p struct {
			SpaceID     string `json:"space_id"`
			Since       int64  `json:"since"`
			WaitSeconds int    `json:"wait_seconds"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.SpaceID == "" {
			return "", fmt.Errorf("space_id is required")
		}
		q := url.Values{}
		q.Set("since", fmt.Sprintf("%d", p.Since))
		if p.WaitSeconds > 0 {
			if p.WaitSeconds > 60 {
				p.WaitSeconds = 60
			}
			q.Set("wait", fmt.Sprintf("%d", p.WaitSeconds))
		}
		return s.passthrough("GET", "/v1/spaces/"+url.PathEscape(p.SpaceID)+"/events?"+q.Encode(), nil)

	case "get_space_file":
		var p struct {
			SpaceID string `json:"space_id"`
			SHA256  string `json:"sha256"`
			OutPath string `json:"out_path"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.SpaceID == "" || p.SHA256 == "" || p.OutPath == "" {
			return "", fmt.Errorf("space_id, sha256, and out_path are required")
		}
		return s.downloadSpaceFile(p.SpaceID, p.SHA256, p.OutPath)

	case "deploy_app":
		var p struct {
			Path       string            `json:"path"`
			Image      string            `json:"image"`
			Kind       string            `json:"kind"`
			Port       int               `json:"port"`
			Env        map[string]string `json:"env"`
			Command    []string          `json:"command"`
			SPA        bool              `json:"spa"`
			HealthPath string            `json:"health_path"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.Port == 0 {
			p.Port = 8080
		}
		raw, warning, err := deployApp(s.a, p.Path, appDeployOptions{
			Kind: p.Kind, Image: p.Image, Port: p.Port, Env: p.Env, Command: p.Command, SPA: p.SPA, HealthPath: p.HealthPath,
		})
		if err != nil {
			return "", err
		}
		result := "Deployment accepted:\n" + prettyRawJSON(raw)
		if warning != "" {
			result += "\nWarning: " + warning
		}
		return result, nil

	case "app_status":
		var raw json.RawMessage
		if err := s.a.json("GET", "/v1/apps/self", nil, &raw); err != nil {
			return "", err
		}
		return prettyRawJSON(raw), nil

	case "app_logs":
		var p struct {
			Tail int `json:"tail"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return "", err
		}
		if p.Tail == 0 {
			p.Tail = 200
		}
		if p.Tail < 1 || p.Tail > 2000 {
			return "", fmt.Errorf("tail must be between 1 and 2000")
		}
		return s.passthrough("GET", "/v1/apps/self/logs?tail="+url.QueryEscape(fmt.Sprintf("%d", p.Tail)), nil)

	case "stop_app":
		var raw json.RawMessage
		if err := s.a.json("POST", "/v1/apps/self/stop", map[string]any{}, &raw); err != nil {
			return "", err
		}
		return prettyRawJSON(raw), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// passthrough runs a REST call and returns the indented JSON body as text.
func (s *mcpServer) passthrough(method, path string, body any) (string, error) {
	var out json.RawMessage
	if err := s.a.json(method, path, body, &out); err != nil {
		return "", err
	}
	var pretty any
	_ = json.Unmarshal(out, &pretty)
	b, _ := json.MarshalIndent(pretty, "", "  ")
	return string(b), nil
}

// upload streams a local file (optionally encrypting) to the folder, returning
// sha256, size, an optional link URL, and (for symmetric encryption) the key.
func (s *mcpServer) upload(path string, share bool, ttl string, once, encrypt bool, sealKeys []string) (sha string, size int64, link, key string, err error) {
	name := filepath.Base(path)
	var reader io.ReadCloser
	switch {
	case len(sealKeys) > 0:
		reader, err = encryptingReader(path, "", sealKeys)
	case encrypt:
		key, err = seal.NewKey()
		if err != nil {
			return "", 0, "", "", err
		}
		reader, err = encryptingReader(path, key, nil)
	default:
		reader, err = os.Open(path)
	}
	if err != nil {
		return "", 0, "", "", err
	}
	defer reader.Close()

	q := url.Values{}
	if share {
		q.Set("share", "1")
	}
	if ttl != "" {
		q.Set("ttl", ttl)
	}
	if once {
		q.Set("once", "1")
	}
	p := "/v1/files/" + url.PathEscape(name)
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	resp, err := s.a.req("PUT", p, reader, "application/octet-stream")
	if err != nil {
		return "", 0, "", "", err
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", 0, "", "", apiError(resp.StatusCode, data)
	}
	var up struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
		Link   *struct {
			URL string `json:"url"`
		} `json:"link"`
	}
	if err := json.Unmarshal(data, &up); err != nil {
		return "", 0, "", "", err
	}
	if up.Link != nil {
		link = up.Link.URL
	}
	return up.SHA256, up.Size, link, key, nil
}

func (s *mcpServer) sendFile(args json.RawMessage) (string, error) {
	return s.sendFileWithIdempotencyGenerator(args, newIdempotencyKey)
}

func (s *mcpServer) sendFileWithIdempotencyGenerator(args json.RawMessage, generate func() (string, error)) (string, error) {
	var p struct {
		To      []string `json:"to"`
		Path    string   `json:"path"`
		Note    string   `json:"note"`
		Subject string   `json:"subject"`
		TTL     string   `json:"ttl"`
		Once    bool     `json:"once"`
		CCOwner bool     `json:"cc_owner"`
		Encrypt bool     `json:"encrypt"`
		Seal    bool     `json:"seal"`
		Repin   bool     `json:"repin"`
		IdemKey string   `json:"idempotency_key"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if len(p.To) == 0 {
		return "", fmt.Errorf("to is required")
	}
	if p.Encrypt && p.Seal {
		return "", fmt.Errorf("encrypt and seal are mutually exclusive")
	}
	if p.Repin && !p.Seal {
		return "", fmt.Errorf("repin requires seal=true")
	}
	if p.Path == "" && (p.Encrypt || p.Seal) {
		return "", fmt.Errorf("encrypt and seal require path")
	}
	idem, err := prepareIdempotencyKeyWith(p.IdemKey, generate)
	if err != nil {
		return "", err
	}
	req := map[string]any{"to": p.To}
	var key string
	var pinNotes []string
	if p.Path != "" {
		var sealKeys []string
		encMode := ""
		if p.Seal {
			ks, notes, err := resolveRecipientKeys(s.a, &s.cfg, p.To, p.Repin)
			if err != nil {
				return "", err
			}
			sealKeys, pinNotes, encMode = ks, notes, "sealed"
		} else if p.Encrypt {
			encMode = "symmetric"
		}
		sha, _, _, k, err := s.upload(p.Path, false, "", false, p.Encrypt, sealKeys)
		if err != nil {
			return "", err
		}
		key = k
		req["file"] = "sha256:" + sha
		if encMode != "" {
			req["enc_mode"] = encMode
		}
	}
	if p.Note != "" {
		req["note"] = p.Note
	}
	if p.Subject != "" {
		req["subject"] = p.Subject
	}
	if p.TTL != "" {
		req["ttl"] = p.TTL
	}
	if p.Once {
		req["once"] = true
	}
	if p.CCOwner {
		req["cc_owner"] = true
	}
	var out struct {
		MessageID string           `json:"message_id"`
		Delivered []map[string]any `json:"delivered"`
	}
	if err := s.a.jsonIdempotent("/v1/send", req, &out, idem); err != nil {
		encMode := ""
		if p.Encrypt {
			encMode = "symmetric"
		} else if p.Seal {
			encMode = "sealed"
		}
		return "", sendFailureError(err, s.a.base, idem, encMode, key, fmt.Sprintf("idempotency_key=%q", idem), req)
	}
	var vias []string
	for _, d := range out.Delivered {
		vias = append(vias, fmt.Sprintf("%v(%v)", d["to"], d["via"]))
	}
	msg := fmt.Sprintf("Sent %s → %s", out.MessageID, strings.Join(vias, ", "))
	if p.Encrypt && key != "" {
		msg += "\nSymmetric key to share out-of-band: " + key
	}
	for _, note := range pinNotes {
		msg += "\nSecurity: " + note
	}
	return msg, nil
}

// download streams ref to out_path, verifying sha256 and decrypting as needed.
// forceSeal decrypts with our own identity for a sealed file fetched by URL or
// sha256 (a msg_ offer auto-detects "sealed" from its enc_mode).
func (s *mcpServer) download(ref, outPath, key string, forceSeal bool) (string, error) {
	var fetchURL, wantSHA, encMode, markRead string
	switch {
	case strings.HasPrefix(ref, "msg_"):
		var m map[string]any
		if err := s.a.json("GET", "/v1/inbox/"+url.PathEscape(ref), nil, &m); err != nil {
			return "", err
		}
		offer, ok := m["offer"].(map[string]any)
		if !ok {
			return "", fmt.Errorf("message has no file offer")
		}
		fetchURL, _ = offer["url"].(string)
		wantSHA, _ = offer["sha256"].(string)
		encMode, _ = offer["enc_mode"].(string)
		markRead = ref // only after success, below
	case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"):
		fetchURL = ref
	case strings.HasPrefix(ref, "sha256:") || len(ref) == 64:
		sha := strings.TrimPrefix(ref, "sha256:")
		fetchURL = s.a.base + "/v1/files/" + sha + "/content"
		wantSHA = sha
	default:
		return "", fmt.Errorf("don't know how to fetch %q", ref)
	}
	if forceSeal {
		encMode = "sealed"
	}

	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return "", err
	}
	if sameOrigin(fetchURL, s.a.base) {
		req.Header.Set("Authorization", "Bearer "+s.a.key)
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := s.a.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", apiError(resp.StatusCode, data)
	}
	if wantSHA == "" {
		wantSHA = strings.TrimPrefix(resp.Header.Get("X-Sha256"), "sha256:")
	}

	switch {
	case key != "": // explicit symmetric key wins
		got, err := verifyAndDecrypt(resp.Body, outPath, wantSHA, key, nil, true)
		if err != nil {
			return "", err
		}
		s.markReadIfSet(markRead)
		if wantSHA != "" {
			return fmt.Sprintf("Wrote %s (decrypted; ciphertext sha256:%s verified)", outPath, got), nil
		}
		return fmt.Sprintf("Wrote %s (decrypted; ciphertext sha256:%s computed, with no expected hash to verify against)", outPath, got), nil
	case encMode == "sealed":
		id, err := loadIdentity(s.cfg)
		if err != nil {
			return "", err
		}
		got, err := verifyAndDecrypt(resp.Body, outPath, wantSHA, "", id, true)
		if err != nil {
			return "", err
		}
		s.markReadIfSet(markRead)
		if wantSHA != "" {
			return fmt.Sprintf("Wrote %s (decrypted with your identity; ciphertext sha256:%s verified)", outPath, got), nil
		}
		return fmt.Sprintf("Wrote %s (decrypted with your identity; ciphertext sha256:%s computed, with no expected hash to verify against)", outPath, got), nil
	case encMode == "symmetric":
		return "", fmt.Errorf("this file is symmetrically encrypted — supply key (atk_...)")
	}

	// Plaintext: stream to disk, verify sha256.
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".agenttransfer-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	tmp.Close()
	if cerr != nil {
		os.Remove(tmp.Name())
		return "", cerr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(got, wantSHA) {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("sha256 mismatch: got %s want %s", got, wantSHA)
	}
	if err := os.Rename(tmp.Name(), outPath); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	s.markReadIfSet(markRead)
	// A file that arrived encrypted but wasn't decrypted is raw ciphertext —
	// tell the model, don't claim it's verified/usable.
	if looksEncrypted(outPath) {
		return fmt.Sprintf("Wrote %s (%d bytes, ciphertext sha256:%s) but it appears to be age-encrypted ciphertext — "+
			"call again with key (atk_...) or seal=true to decrypt", outPath, n, got), nil
	}
	if wantSHA != "" {
		return fmt.Sprintf("Wrote %s (%d bytes, sha256:%s verified)", outPath, n, got), nil
	}
	return fmt.Sprintf("Wrote %s (%d bytes, sha256:%s computed, with no expected hash to verify against)", outPath, n, got), nil
}

// markReadIfSet marks an inbox message read after a successful download.
func (s *mcpServer) markReadIfSet(ref string) {
	if ref != "" {
		_ = s.a.json("POST", "/v1/inbox/"+url.PathEscape(ref)+"/read", map[string]any{}, nil)
	}
}

// postToSpace posts a message and/or a local file to a space's shared stream.
// A file arg is a LOCAL PATH: it is streamed into the caller's folder first
// (any size — bytes never enter the model's context), then offered to the space
// by its "sha256:" reference — mirroring how sendFile turns a path into an
// offer. Returns the created event.
func (s *mcpServer) postToSpace(args json.RawMessage) (string, error) {
	var p struct {
		SpaceID string `json:"space_id"`
		Text    string `json:"text"`
		File    string `json:"file"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", err
	}
	if p.SpaceID == "" {
		return "", fmt.Errorf("space_id is required")
	}
	if p.Text == "" && p.File == "" {
		return "", fmt.Errorf("text or file is required")
	}
	req := map[string]any{}
	if p.File != "" {
		// Plaintext into the folder (space files are gated by membership, not a
		// link), then offer by content hash — the same "sha256:..." ref send uses.
		sha, _, _, _, err := s.upload(p.File, false, "", false, false, nil)
		if err != nil {
			return "", err
		}
		req["file"] = "sha256:" + sha
	}
	if p.Text != "" {
		req["text"] = p.Text
	}
	var out struct {
		Event json.RawMessage `json:"event"`
	}
	if err := s.a.json("POST", "/v1/spaces/"+url.PathEscape(p.SpaceID)+"/events", req, &out); err != nil {
		return "", err
	}
	var pretty any
	_ = json.Unmarshal(out.Event, &pretty)
	b, _ := json.MarshalIndent(pretty, "", "  ")
	return "Posted event:\n" + string(b), nil
}

// downloadSpaceFile streams a file shared in a space to outPath, verifying its
// sha256 — the space-membership analogue of download's plaintext path. Space
// files are gated by membership (always same-origin, so the bearer key always
// attaches) and are never encrypted by the bridge. Returns a one-line summary;
// never the file bytes.
func (s *mcpServer) downloadSpaceFile(spaceID, sha, outPath string) (string, error) {
	wantSHA := strings.TrimPrefix(sha, "sha256:")
	fetchURL := s.a.base + "/v1/spaces/" + url.PathEscape(spaceID) + "/files/" + url.PathEscape(wantSHA) + "/content"
	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.a.key)
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := s.a.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", apiError(resp.StatusCode, data)
	}
	headerSHA := strings.TrimPrefix(resp.Header.Get("X-Sha256"), "sha256:")

	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".agenttransfer-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	tmp.Close()
	if cerr != nil {
		os.Remove(tmp.Name())
		return "", cerr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(got, wantSHA) {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("sha256 mismatch: got %s want %s", got, wantSHA)
	}
	if headerSHA != "" && !strings.EqualFold(got, headerSHA) {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("sha256 mismatch vs X-Sha256 header: got %s header %s", got, headerSHA)
	}
	if err := os.Rename(tmp.Name(), outPath); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return fmt.Sprintf("Wrote %s (%d bytes, sha256:%s verified)", outPath, n, got), nil
}
