package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

const (
	maxMCPRequestBytes         = 4 << 20
	latestMCPProtocolVersion   = "2025-11-25"
	previousMCPProtocolVersion = "2025-06-18"
)

func negotiateMCPProtocolVersion(requested string) string {
	switch requested {
	case latestMCPProtocolVersion, previousMCPProtocolVersion:
		return requested
	default:
		return latestMCPProtocolVersion
	}
}

// validMCPOrigin enforces the Streamable HTTP DNS-rebinding defense. The
// Origin header is an origin serialization, not a general URL: a path, query,
// fragment, credentials, multiple values, or the special value "null" is
// invalid. Requests from non-browser clients commonly omit Origin and remain
// valid.
func (s *Server) validMCPOrigin(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, err := url.Parse(values[0])
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" || origin.User != nil ||
		origin.Opaque != "" || origin.Path != "" || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" {
		return false
	}
	base, err := url.Parse(s.BaseURL())
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.Opaque != "" {
		return false
	}
	return strings.EqualFold(origin.Scheme, base.Scheme) && strings.EqualFold(origin.Host, base.Host)
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !s.validMCPOrigin(r) {
		errJSON(w, http.StatusForbidden, "Origin must match the configured AgentTransfer origin")
		return
	}

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

	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPRequestBytes+1))
	if err != nil {
		errJSON(w, http.StatusBadRequest, "read failed")
		return
	}
	if len(body) > maxMCPRequestBytes {
		errJSON(w, http.StatusRequestEntityTooLarge, "MCP request body exceeds 4 MiB")
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
		s.rpcReply(w, req.ID, map[string]any{
			"protocolVersion": negotiateMCPProtocolVersion(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agenttransfer", "version": Version},
			"instructions": "AgentTransfer: file transfer for AI agents. Upload files to your folder, " +
				"mint expiring share links, send them to other agents (or humans) by email, " +
				"and poll your inbox. Supported transfer and app-lifecycle events emit best-effort signed receipts.",
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
		out, callErr := s.mcpCall(r.Context(), agent, p.Name, p.Arguments)
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
		"description": "Your authenticated identity/provenance, public contact, encryption recipient, storage/limits, remote-recipient circle, and app-hosting readiness/status.",
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
			"download link and a machine-readable manifest. A stable idempotency_key is required so uncertain retries cannot deliver twice.",
		"inputSchema": obj(map[string]any{
			"to":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "recipient email addresses"},
			"file":     str("optional: \"sha256:...\" or folder filename to attach as a link"),
			"note":     str("message text"),
			"subject":  str("optional subject"),
			"ttl":      str("link TTL like \"3h\""),
			"once":     boolp("burn-after-read link"),
			"reply_to": str("inbox message id (msg_...) this replies to"),
			"cc_owner": boolp("CC your human owner"),
			"enc_mode": str("optional client-encryption marker: symmetric or sealed"),
			"idempotency_key": map[string]any{
				"type": "string", "minLength": 1, "maxLength": store.MaxIdempotencyKeyBytes,
				"pattern": "^[!-~]+$", "description": "required stable visible-ASCII key; reuse only for an uncertain retry of this exact send",
			},
		}, "to", "idempotency_key"),
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
	{
		"name":        "app_status",
		"description": "Get this agent's hosted app eligibility, public URL, status, active deployment, and storage usage.",
		"inputSchema": obj(map[string]any{}),
	},
	{
		"name":        "deploy_app_image",
		"description": "Deploy an OCI image as this verified agent's hosted app. Hosted HTTP MCP cannot read local paths or upload source/static bundles; for those, run the local stdio bridge and call deploy_app with a local path.",
		"inputSchema": obj(map[string]any{
			"image":       str("OCI image reference (required)"),
			"port":        intp("container HTTP port (default 8080)"),
			"env":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "container environment variables; values are never returned"},
			"command":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "container argv override"},
			"health_path": str("HTTP health-check path inside the app (default /)"),
		}, "image"),
	},
	{
		"name":        "app_logs",
		"description": "Read a bounded tail of this verified agent's container app logs.",
		"inputSchema": obj(map[string]any{"tail": intp("recent lines, 1-2000 (default 200)")}),
	},
	{
		"name":        "stop_app",
		"description": "Stop this verified agent's running app without deleting its configuration or data.",
		"inputSchema": obj(map[string]any{}),
	},
}

func validateMCPIdempotencyKey(key string) error {
	if key == "" || len(key) > store.MaxIdempotencyKeyBytes {
		return fmt.Errorf("idempotency_key must be 1-%d visible ASCII characters without spaces", store.MaxIdempotencyKeyBytes)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return errors.New("idempotency_key must contain only visible ASCII characters without spaces")
		}
	}
	return nil
}

// replayMCPSend converts the durable REST-shaped send response into the same
// hosted tool success/error that originally produced it. Sharing this storage
// shape also makes one key safe across REST and hosted MCP transports.
func replayMCPSend(record store.IdempotencyRecord) (any, error) {
	if record.Status >= http.StatusBadRequest {
		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(record.Response, &body); err != nil || body.Error == "" {
			return nil, errors.New("stored idempotent send failure is corrupt")
		}
		return nil, errors.New(body.Error)
	}
	if !json.Valid(record.Response) {
		return nil, errors.New("stored idempotent send result is corrupt")
	}
	return json.RawMessage(append([]byte(nil), record.Response...)), nil
}

func (s *Server) mcpWhoami(ctx context.Context, agent store.Agent) (map[string]any, error) {
	out, err := s.whoamiProjection(ctx, agent)
	if err != nil {
		return nil, err
	}
	out["api"] = s.BaseURL() + "/v1"
	// Retain the original hosted-MCP aliases while exposing the full REST
	// projection above. Existing clients need not migrate atomically.
	if storage, ok := out["storage"].(map[string]any); ok {
		out["storage_used"] = storage["used"]
		out["storage_quota"] = storage["quota"]
		if expiry, exists := storage["files_expire_after"]; exists {
			out["files_expire_after"] = expiry
		}
	}
	return out, nil
}

func (s *Server) mcpCall(ctx context.Context, agent store.Agent, name string, args json.RawMessage) (any, error) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch name {
	case "whoami":
		return s.mcpWhoami(ctx, agent)

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
		var p struct {
			To             []string `json:"to"`
			File           string   `json:"file"`
			Note           string   `json:"note"`
			Subject        string   `json:"subject"`
			TTL            string   `json:"ttl"`
			Once           bool     `json:"once"`
			ReplyTo        string   `json:"reply_to"`
			CCOwner        bool     `json:"cc_owner"`
			EncMode        string   `json:"enc_mode"`
			IdempotencyKey string   `json:"idempotency_key"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		if err := validateMCPIdempotencyKey(p.IdempotencyKey); err != nil {
			return nil, err
		}
		req := normalizeSendRequest(sendRequest{
			To: p.To, File: p.File, Note: p.Note, Subject: p.Subject, TTL: p.TTL,
			Once: p.Once, ReplyTo: p.ReplyTo, CCOwner: p.CCOwner, EncMode: p.EncMode,
		})
		requestHash, err := sendRequestHash(req)
		if err != nil {
			return nil, fmt.Errorf("fingerprint send request: %w", err)
		}
		record, created, err := s.st.BeginIdempotent(agent.ID, p.IdempotencyKey, requestHash)
		switch {
		case errors.Is(err, store.ErrIdempotencyConflict):
			return nil, errors.New("idempotency_key is already bound to a different send request")
		case errors.Is(err, store.ErrLimit):
			return nil, err
		case err != nil:
			return nil, fmt.Errorf("reserve idempotency_key: %w", err)
		case !created && record.Status == 0:
			return nil, errors.New("this idempotency_key has an unfinished prior request; its outcome cannot be replayed")
		case !created:
			return replayMCPSend(record)
		}

		res, status, sendErr := s.performSend(agent, req)
		var response any = res
		if sendErr != nil {
			response = map[string]string{"error": sendErr.Error()}
		}
		body, err := sendJSONBody(response)
		if err != nil {
			return nil, fmt.Errorf("encode send result: %w", err)
		}
		if err := s.st.CompleteIdempotent(agent.ID, p.IdempotencyKey, requestHash, status, body); err != nil {
			return nil, fmt.Errorf("send finished but its idempotent result could not be persisted; retry only with the same key: %w", err)
		}
		if sendErr != nil {
			return nil, sendErr
		}
		return json.RawMessage(body), nil

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
		if err := s.st.MarkRead(agent.ID, p.ID); err != nil {
			return nil, err
		}
		m.Read = true
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
		downloadActor := agent.Email
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
			downloadActor = s.agentEmailByID(l.AgentID)
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
			downloadURL := s.BaseURL() + "/v1/files/" + sha + "/content"
			note := "file exceeds the 1MiB inline cap; fetch it over HTTPS with your key"
			if viaLink != "" {
				// A capability-link downloader need not own the sender's folder row.
				// Return the capability URL, not the owner-only folder endpoint.
				downloadURL = s.linkURL(viaLink) + "?dl=1"
				note = "file exceeds the 1MiB inline cap; fetch it from the share URL and verify the sha256"
			}
			return map[string]any{
				"note":   note,
				"sha256": sha,
				"size":   info.Size(),
				"url":    downloadURL,
			}, nil
		}
		var reader io.Reader = blob
		var guarded *severReader
		if viaLink != "" {
			guarded = &severReader{ReadSeeker: blob, s: s, token: viaLink}
			reader = guarded
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			if guarded != nil && guarded.severed {
				return nil, errors.New("link was revoked during download")
			}
			return nil, err
		}
		// A link-served download counts on the link, exactly like GET /f/.
		target := "mcp"
		if viaLink != "" {
			if s.isSevered(viaLink) {
				return nil, errors.New("link was revoked during download")
			}
			if err := s.st.CountActiveDownload(viaLink); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil, errors.New("link was revoked or expired during download")
				}
				return nil, fmt.Errorf("account link download: %w", err)
			}
			s.metrics.downloads.Add(1)
			target = "link:" + viaLink
		}
		s.appendReceipt(downloadActor, receipt.ActionDownloaded, sha, int64(len(data)), target, "")
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

	case "app_status":
		eligible, reason := s.appEligibility(agent)
		app, err := s.st.AppByAgentID(agent.ID)
		if errors.Is(err, store.ErrNotFound) {
			out := map[string]any{"eligible": eligible, "domain": s.cfg.AppDomain, "app": nil}
			if reason != "" {
				out["reason"] = reason
			}
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("app identity: %w", err)
		}
		out := map[string]any{"eligible": eligible, "domain": s.cfg.AppDomain, "app": s.appView(ctx, agent, app)}
		if reason != "" {
			out["reason"] = reason
		}
		return out, nil

	case "deploy_app":
		// The local stdio bridge owns path-based deployment because only it can
		// read the caller's filesystem and stream a bundle without putting bytes
		// in model context. Keep this alias as a useful error for clients that use
		// the local tool name against hosted MCP.
		return nil, errors.New("hosted MCP cannot access local paths or deploy source/static bundles; run the local stdio bridge and call deploy_app there, or use deploy_app_image with an OCI image")

	case "deploy_app_image":
		if len(args) > 1<<20 {
			return nil, errors.New("deployment configuration exceeds 1MiB")
		}
		var p struct {
			Image      string            `json:"image"`
			Port       int               `json:"port"`
			Env        map[string]string `json:"env"`
			Command    []string          `json:"command"`
			HealthPath string            `json:"health_path"`
			// Give path/source callers the intended local-bridge explanation,
			// even though these fields are deliberately absent from tools/list.
			Path   string `json:"path"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.Path) != "" || strings.TrimSpace(p.Source) != "" {
			return nil, errors.New("hosted MCP cannot upload local source; run the local stdio bridge and call deploy_app with that path")
		}
		p.Image = strings.TrimSpace(p.Image)
		if p.Image == "" {
			return nil, errors.New("image is required; source/static deployment is available through the local stdio bridge's deploy_app tool")
		}
		if p.Port == 0 {
			p.Port = 8080
		}
		if p.Port < 1 || p.Port > 65535 {
			return nil, errors.New("port must be between 1 and 65535")
		}
		if len(p.Env) > 64 {
			return nil, errors.New("at most 64 environment variables are allowed")
		}
		if len(p.Command) > 64 {
			return nil, errors.New("command has too many arguments (max 64)")
		}
		if p.HealthPath == "" {
			p.HealthPath = "/"
		}
		if err := validateAppHealthPath(p.HealthPath); err != nil {
			return nil, err
		}
		app, deployment, err := s.deployAgentApp(ctx, agent, appDeployRequest{
			Kind: store.AppKindContainer, Image: p.Image, Port: p.Port,
			Env: p.Env, Command: p.Command, HealthPath: p.HealthPath,
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"app": s.appView(ctx, agent, app),
			// Do not return deployment.Config here. It currently contains only
			// env keys, but omitting it makes secret non-disclosure structural if
			// the stored config grows in the future.
			"deployment": map[string]any{
				"id": deployment.ID, "kind": deployment.Kind,
				"status": deployment.Status, "created_at": deployment.CreatedAt,
				"activated_at": deployment.ActivatedAt,
			},
		}, nil

	case "app_logs":
		var p struct {
			Tail int `json:"tail"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		if p.Tail == 0 {
			p.Tail = 200
		}
		if p.Tail < 1 || p.Tail > 2000 {
			return nil, errors.New("tail must be between 1 and 2000")
		}
		logResult, status, err := s.appRuntimeLogResult(ctx, agent.ID, p.Tail)
		if err != nil {
			return nil, fmt.Errorf("logs failed: %w", err)
		}
		logs := logResult.Output
		const maxMCPLogBytes = 256 << 10
		truncated := logResult.Truncated || len(logs) > maxMCPLogBytes
		if truncated {
			logs = "[older output truncated]\n" + logs[len(logs)-maxMCPLogBytes:]
		}
		return map[string]any{"logs": logs, "status": status, "truncated": truncated}, nil

	case "stop_app":
		app, err := s.stopAgentApp(ctx, agent)
		if err != nil {
			return nil, fmt.Errorf("stop failed: %w", err)
		}
		return map[string]any{"app": s.appView(ctx, agent, app)}, nil
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}
