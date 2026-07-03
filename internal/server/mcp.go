package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// AgentTransfer speaks MCP (Streamable HTTP) natively at /mcp with the same
// bearer key as the REST API. This is a deliberately minimal, dependency-free
// implementation of the subset every client uses: initialize, tools/list,
// tools/call, ping. Responses are plain JSON (allowed by the spec); there is
// no server-initiated stream.

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	// JSON responses only — no server push stream, no sessions to delete.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	tok := bearer(r)
	agent, err := s.st.AgentByKey(tok)
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "invalid or missing API key (Authorization: Bearer at_live_...)")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		errJSON(w, http.StatusBadRequest, "read failed")
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.rpcReply(w, nil, nil, &rpcError{-32700, "parse error"})
		return
	}

	// Notifications get acknowledged and dropped.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := p.ProtocolVersion
		if version == "" {
			version = "2025-03-26"
		}
		s.rpcReply(w, req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agenttransfer", "version": Version},
			"instructions": "AgentTransfer: file transfer for AI agents. Upload files to your folder, " +
				"mint expiring share links, send them to other agents (or humans) by email, " +
				"and poll your inbox. Every action leaves a signed receipt.",
		}, nil)
	case "ping":
		s.rpcReply(w, req.ID, map[string]any{}, nil)
	case "tools/list":
		s.rpcReply(w, req.ID, map[string]any{"tools": mcpTools}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.rpcReply(w, req.ID, nil, &rpcError{-32602, "invalid params"})
			return
		}
		out, callErr := s.mcpCall(agent, p.Name, p.Arguments)
		if callErr != nil {
			// Tool-level failures are results with isError, not RPC errors.
			s.rpcReply(w, req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": callErr.Error()}},
				"isError": true,
			}, nil)
			return
		}
		text, _ := json.MarshalIndent(out, "", "  ")
		s.rpcReply(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(text)}},
		}, nil)
	default:
		s.rpcReply(w, req.ID, nil, &rpcError{-32601, "method not found: " + req.Method})
	}
}

func (s *Server) rpcReply(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0"}
	if id != nil {
		resp["id"] = json.RawMessage(id)
	} else {
		resp["id"] = nil
	}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	writeJSON(w, http.StatusOK, resp)
}

func obj(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func str(desc string) map[string]any   { return map[string]any{"type": "string", "description": desc} }
func boolp(desc string) map[string]any { return map[string]any{"type": "boolean", "description": desc} }
func intp(desc string) map[string]any  { return map[string]any{"type": "integer", "description": desc} }

var mcpTools = []map[string]any{
	{
		"name":        "whoami",
		"description": "Your agent identity: email address, storage usage and quota, owner verification, and remote-recipient circle.",
		"inputSchema": obj(map[string]any{}),
	},
	{
		"name":        "list_files",
		"description": "List the files in your folder (persistent unless unclaimed).",
		"inputSchema": obj(map[string]any{}),
	},
	{
		"name": "upload_file",
		"description": "Upload a small file into your folder from inline content (≤1MiB as text or base64). " +
			"For anything bigger, PUT the raw bytes to {api}/v1/files/{name} with your bearer key (e.g. curl -T).",
		"inputSchema": obj(map[string]any{
			"name":           str("filename"),
			"content_text":   str("UTF-8 file content"),
			"content_base64": str("base64 file content (binary)"),
			"share":          boolp("also mint a share link"),
			"ttl":            str("share link TTL like \"3h\" (max 24h)"),
			"once":           boolp("burn-after-read share link"),
		}, "name"),
	},
	{
		"name":        "share_file",
		"description": "Mint an ephemeral share link (≤24h) for a file already in your folder.",
		"inputSchema": obj(map[string]any{
			"file": str("\"sha256:...\" or a folder filename"),
			"ttl":  str("TTL like \"3h\" (max 24h)"),
			"once": boolp("burn-after-read"),
		}, "file"),
	},
	{
		"name": "send",
		"description": "Send a message and/or a file to other agents or humans by email. Same-instance " +
			"agents receive it instantly in their inbox; everyone else gets a normal email with a " +
			"download link and a machine-readable manifest.",
		"inputSchema": obj(map[string]any{
			"to":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "recipient email addresses"},
			"file":     str("optional: \"sha256:...\" or folder filename to attach as a link"),
			"note":     str("message text"),
			"subject":  str("optional subject"),
			"ttl":      str("link TTL like \"3h\""),
			"once":     boolp("burn-after-read link"),
			"reply_to": str("inbox message id (msg_...) this replies to"),
			"cc_owner": boolp("CC your human owner"),
		}, "to"),
	},
	{
		"name":        "check_inbox",
		"description": "List inbox messages. Set wait_seconds to long-poll until something arrives.",
		"inputSchema": obj(map[string]any{
			"unread":       boolp("only unread (default true)"),
			"wait_seconds": intp("long-poll up to this many seconds (max 60)"),
		}),
	},
	{
		"name":        "read_message",
		"description": "Fetch one inbox message by id and mark it read.",
		"inputSchema": obj(map[string]any{"id": str("message id (msg_...)")}, "id"),
	},
	{
		"name": "download_file",
		"description": "Download a file. Accepts a sha256 from your folder or an AgentTransfer share URL " +
			"from a message offer. Returns base64 content up to 1MiB; larger files return the URL to fetch.",
		"inputSchema": obj(map[string]any{
			"sha256": str("hash of a file in your folder"),
			"url":    str("share link URL from an offer"),
		}),
	},
	{
		"name":        "create_upload_request",
		"description": "Mint a one-time browser upload page a human can drop a file into; it lands in your inbox.",
		"inputSchema": obj(map[string]any{
			"note": str("what you want them to upload"),
			"ttl":  str("how long the page lives, like \"24h\""),
		}),
	},
	{
		"name":        "get_receipts",
		"description": "Your signed receipt trail (uploads, sends, downloads, expiries).",
		"inputSchema": obj(map[string]any{"limit": intp("max receipts")}),
	},
}

func (s *Server) mcpCall(agent store.Agent, name string, args json.RawMessage) (any, error) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch name {
	case "whoami":
		used, _ := s.st.StorageUsed(agent.ID)
		circleUsed, _ := s.st.CountHumanRecipients(agent.ID)
		out := map[string]any{
			"agent_id": agent.ID, "name": agent.Name, "email": agent.Email,
			"instance": s.st.Instance(), "owner_verified": agent.OwnerVerified,
			// Tier-aware, matching REST whoami: unverified agents see the
			// reduced quota that's actually enforced, not the full one.
			"storage_used": used, "storage_quota": s.quotaFor(agent),
			"remote_recipients": map[string]any{"used": circleUsed, "max": s.humanCircleMax(agent)},
			"email_enabled":     s.emailCapable(),
			"api":               s.BaseURL() + "/v1",
		}
		if exp := s.fileExpiry(agent); exp > 0 {
			out["files_expire_after"] = s.cfg.UnverifiedFileTTL.String()
		}
		return out, nil

	case "list_files":
		files, err := s.st.ListFiles(agent.ID)
		if err != nil {
			return nil, err
		}
		return map[string]any{"files": files}, nil

	case "upload_file":
		var p struct {
			Name          string `json:"name"`
			ContentText   string `json:"content_text"`
			ContentBase64 string `json:"content_base64"`
			Share         bool   `json:"share"`
			TTL           string `json:"ttl"`
			Once          bool   `json:"once"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		var data []byte
		switch {
		case p.ContentBase64 != "":
			var err error
			data, err = base64.StdEncoding.DecodeString(p.ContentBase64)
			if err != nil {
				return nil, fmt.Errorf("bad content_base64: %w", err)
			}
		case p.ContentText != "":
			data = []byte(p.ContentText)
		default:
			return nil, fmt.Errorf("no content: pass content_text or content_base64, or PUT raw bytes to %s/v1/files/%s", s.BaseURL(), p.Name)
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("inline content is capped at 1MiB; PUT the raw bytes to %s/v1/files/%s instead", s.BaseURL(), p.Name)
		}
		ttl, err := s.ttlFrom(p.TTL, s.cfg.DefaultTTL)
		if err != nil {
			return nil, err
		}
		res, _, err := s.performUpload(agent, p.Name, "", strings.NewReader(string(data)), p.Share || p.TTL != "" || p.Once, ttl, p.Once)
		if err != nil {
			return nil, err
		}
		return res, nil

	case "share_file":
		var p struct {
			File string `json:"file"`
			TTL  string `json:"ttl"`
			Once bool   `json:"once"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		f, err := s.resolveFile(agent, p.File)
		if err != nil {
			return nil, err
		}
		ttl, err := s.ttlFrom(p.TTL, s.cfg.DefaultTTL)
		if err != nil {
			return nil, err
		}
		l, err := s.st.CreateLink(agent.ID, f.SHA256, f.Name, f.MIME, f.Size, p.Once, ttl)
		if err != nil {
			return nil, err
		}
		return s.linkJSON(l), nil

	case "send":
		var p sendRequest
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		res, _, err := s.performSend(agent, p)
		if err != nil {
			return nil, err
		}
		return res, nil

	case "check_inbox":
		var p struct {
			Unread      *bool `json:"unread"`
			WaitSeconds int   `json:"wait_seconds"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		unread := true
		if p.Unread != nil {
			unread = *p.Unread
		}
		if p.WaitSeconds > 60 {
			p.WaitSeconds = 60
		}
		deadline := time.Now().Add(time.Duration(p.WaitSeconds) * time.Second)
		ch, cancel := s.hub.subscribe(agent.ID)
		defer cancel()
		for {
			msgs, err := s.st.ListInbox(agent.ID, unread, "", 0)
			if err != nil {
				return nil, err
			}
			if len(msgs) > 0 || time.Now().After(deadline) {
				out := make([]map[string]any, 0, len(msgs))
				for _, m := range msgs {
					out = append(out, s.messageJSON(m))
				}
				return map[string]any{"messages": out}, nil
			}
			wait := time.Until(deadline)
			if wait > 5*time.Second {
				wait = 5 * time.Second
			}
			select {
			case <-ch:
			case <-time.After(wait):
			}
		}

	case "read_message":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		m, err := s.st.GetMessage(agent.ID, p.ID)
		if err != nil {
			return nil, errors.New("no such message")
		}
		_ = s.st.MarkRead(agent.ID, p.ID)
		return s.messageJSON(m), nil

	case "download_file":
		var p struct {
			SHA256 string `json:"sha256"`
			URL    string `json:"url"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		var sha, viaLink string
		switch {
		case p.SHA256 != "":
			f, err := s.st.FileBySHA(agent.ID, strings.TrimPrefix(strings.ToLower(p.SHA256), "sha256:"))
			if err != nil {
				return nil, errors.New("no such file in your folder")
			}
			sha = f.SHA256
		case p.URL != "":
			// Same-instance share links only: never fetch foreign URLs (SSRF).
			token, ok := strings.CutPrefix(p.URL, s.BaseURL()+"/f/")
			if !ok {
				return map[string]any{
					"note": "that link is on another instance; fetch it directly over HTTPS and verify the sha256 from the offer",
					"url":  p.URL,
				}, nil
			}
			token, _, _ = strings.Cut(token, "?")
			l, err := s.st.GetLink(token)
			if err != nil || l.Status != "active" || l.ExpiresAt <= time.Now().Unix() {
				return nil, errors.New("link is expired, revoked, or unknown")
			}
			if l.Once {
				// Burn-after-read must go through the real burn path (single
				// flight + burn-on-completion); serving bytes here would let
				// the link be read forever without burning.
				return map[string]any{
					"note":   "this is a single-download (burn-after-read) link; fetch it once with `?dl=1` — the download consumes it",
					"url":    p.URL + "?dl=1",
					"sha256": l.SHA256,
					"size":   l.Size,
				}, nil
			}
			sha = l.SHA256
			viaLink = token
		default:
			return nil, errors.New("pass sha256 or url")
		}
		blob, err := s.st.OpenBlob(sha)
		if err != nil {
			return nil, errors.New("blob missing")
		}
		defer blob.Close()
		info, err := blob.Stat()
		if err != nil {
			return nil, err
		}
		if info.Size() > 1<<20 {
			return map[string]any{
				"note":   "file exceeds the 1MiB inline cap; fetch it over HTTPS with your key",
				"sha256": sha,
				"size":   info.Size(),
				"url":    s.BaseURL() + "/v1/files/" + sha + "/content",
			}, nil
		}
		data, err := io.ReadAll(blob)
		if err != nil {
			return nil, err
		}
		// A link-served download counts on the link, exactly like GET /f/.
		target := "mcp"
		if viaLink != "" {
			_ = s.st.CountDownload(viaLink)
			s.metrics.downloads.Add(1)
			target = "link:" + viaLink
		}
		_, _ = s.st.AppendReceipt(agent.Email, receipt.ActionDownloaded, sha, int64(len(data)), target, "")
		return map[string]any{"sha256": sha, "size": len(data), "content_base64": base64.StdEncoding.EncodeToString(data)}, nil

	case "create_upload_request":
		var p struct {
			Note string `json:"note"`
			TTL  string `json:"ttl"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		ttl, err := s.ttlFrom(p.TTL, s.cfg.MaxTTL)
		if err != nil {
			return nil, err
		}
		u, err := s.st.CreateUploadRequest(agent.ID, p.Note, ttl)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"upload_url": s.BaseURL() + "/u/" + u.Token,
			"expires_at": time.Unix(u.ExpiresAt, 0).UTC().Format(time.RFC3339),
		}, nil

	case "get_receipts":
		var p struct {
			Limit int `json:"limit"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		rs, err := s.st.ListReceipts(agent.Email, p.Limit)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"receipt_pubkey": receipt.FormatPublicKey(s.st.PublicKey()),
			"receipts":       rs,
		}, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
