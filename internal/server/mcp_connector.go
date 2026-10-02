package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shehryarsaroya/agenttransfer/internal/proto"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// The hosted MCP server is AgentTransfer's connector surface: ChatGPT plugins,
// Claude connectors, Muse, Gemini and any other MCP client reach a person's
// drive through it. Tools are written for an assistant in a chat — save this,
// find that, give me a link, send it to Dana — and never move file bytes
// through the model except when it asks to read a file's contents.

const (
	// modernMCPProtocolVersion is the stateless protocol (server/discover,
	// per-request _meta). Clients still on initialize keep working.
	modernMCPProtocolVersion = "2026-07-28"
	mcpMetaVersion           = "io.modelcontextprotocol/protocolVersion"
	mcpMetaClientCaps        = "io.modelcontextprotocol/clientCapabilities"
	mcpMetaServerInfo        = "io.modelcontextprotocol/serverInfo"
	mcpScope                 = "files"
	readTextMax              = 100_000 // chars of text returned by read_file
	readImageMax             = 4 << 20 // bytes of image returned inline
	inlineSaveMax            = 8 << 20 // decoded bytes accepted inline by save_file
)

// mcpRich lets a tool return its own content items (e.g. an image) plus the
// structured object.
type mcpRich struct {
	content    []map[string]any
	structured any
}

func annotations(readOnly, destructive, idempotent, openWorld bool) map[string]any {
	return map[string]any{
		"readOnlyHint":    readOnly,
		"destructiveHint": destructive,
		"idempotentHint":  idempotent,
		"openWorldHint":   openWorld,
	}
}

func (s *Server) tool(name, title, desc string, schema, ann map[string]any, meta map[string]any) map[string]any {
	t := map[string]any{
		"name": name, "title": title, "description": desc, "inputSchema": schema,
		"annotations": map[string]any{"title": title},
	}
	for k, v := range ann {
		t["annotations"].(map[string]any)[k] = v
	}
	if s.cfg.Accounts {
		schemes := []map[string]any{{"type": "oauth2", "scopes": []string{mcpScope}}}
		t["securitySchemes"] = schemes
		if meta == nil {
			meta = map[string]any{}
		}
		meta["securitySchemes"] = schemes
	}
	if len(meta) > 0 {
		t["_meta"] = meta
	}
	return t
}

func fileRefSchema() map[string]any {
	return str(`a file in your drive: its name (e.g. "report.pdf") or "sha256:<hash>"`)
}

// mcpToolList is the advertised tool set. Older hosted tool names
// (upload_file, share_file, download_file, get_receipts) stay callable for
// existing agents but are not listed.
func (s *Server) mcpToolList() []map[string]any {
	fileParam := map[string]any{
		"type":        "object",
		"description": "a file the user attached in the chat (ChatGPT passes it here automatically)",
		"properties": map[string]any{
			"download_url": map[string]any{"type": "string"},
			"file_id":      map[string]any{"type": "string"},
			"mime_type":    map[string]any{"type": "string"},
			"file_name":    map[string]any{"type": "string"},
		},
		"required": []string{"download_url", "file_id"},
	}
	tools := []map[string]any{
		s.tool("save_file", "Save a file",
			"Save a file to the user's AgentTransfer drive — the one drive shared by every AI they've connected "+
				"(ChatGPT, Claude, Muse, coding agents). Pass a file the user attached, or text content you wrote "+
				"(with a name like \"notes.md\"). Returns the saved file's name, size and sha256.",
			obj(map[string]any{
				"file":           fileParam,
				"name":           str("file name to save under (required with content)"),
				"content":        str("UTF-8 text content to save, e.g. a document or CSV you wrote"),
				"content_base64": str("small binary content, base64 (up to 8 MiB decoded)"),
			}),
			annotations(false, false, false, false),
			map[string]any{
				"openai/fileParams":              []string{"file"},
				"openai/toolInvocation/invoking": "Saving to AgentTransfer…",
				"openai/toolInvocation/invoked":  "Saved to AgentTransfer",
			}),
		s.tool("list_files", "List files",
			"List the files in the user's AgentTransfer drive, newest first. Optionally filter by part of the name.",
			obj(map[string]any{
				"query": str("only files whose name contains this text"),
				"limit": intp("max files to return (default 50, max 500)"),
			}),
			annotations(true, false, true, false), nil),
		s.tool("read_file", "Read a file",
			"Read a file from the user's drive. Text files (code, markdown, CSV, JSON…) come back as text, "+
				"images as images; anything else returns its details and a download link for the user.",
			obj(map[string]any{"file": fileRefSchema()}, "file"),
			annotations(true, false, true, false), nil),
		s.tool("get_link", "Get a download link",
			"Create an expiring download link for a file in the user's drive, to share with a person or another "+
				"service. Anyone with the link can download until it expires (default 3h, max 24h).",
			obj(map[string]any{
				"file": fileRefSchema(),
				"ttl":  str(`how long the link works, like "1h" or "24h"`),
				"once": boolp("link works for one download only"),
			}, "file"),
			annotations(false, false, false, true), nil),
		s.tool("send", "Send a file or message",
			"Send a file from the user's drive (and/or a note) to agents or people by address, e.g. "+
				"\"dana@agenttransfer.dev\" reaches every agent Dana has connected. Recipients get a hash-verified "+
				"download offer in their inbox; outside addresses get an email with the link. Pass any unique "+
				"idempotency_key (reuse it only to retry this exact send).",
			obj(map[string]any{
				"to":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "recipient addresses"},
				"file":     fileRefSchema(),
				"note":     str("message text"),
				"subject":  str("optional subject"),
				"ttl":      str(`how long the download link works, like "3h"`),
				"once":     boolp("link works for one download only"),
				"reply_to": str("inbox message id (msg_...) this replies to"),
				"cc_owner": boolp("CC the user's email"),
				"enc_mode": str("optional client-encryption marker: symmetric or sealed"),
				"idempotency_key": map[string]any{
					"type": "string", "minLength": 1, "maxLength": store.MaxIdempotencyKeyBytes,
					"pattern": "^[!-~]+$", "description": "a unique string you choose for this send",
				},
			}, "to", "idempotency_key"),
			annotations(false, false, false, true),
			map[string]any{"openai/toolInvocation/invoking": "Sending…", "openai/toolInvocation/invoked": "Sent"}),
		s.tool("check_inbox", "Check inbox",
			"List messages and file offers other agents and people sent to this AI. Set wait_seconds to wait for "+
				"something to arrive.",
			obj(map[string]any{
				"unread":       boolp("only unread messages (default true)"),
				"wait_seconds": intp("wait up to this many seconds for a new message (max 60)"),
			}),
			annotations(true, false, true, false), nil),
		s.tool("read_message", "Open a message",
			"Open one inbox message (and mark it read). File offers list each file's name, size, sha256 and link.",
			obj(map[string]any{"id": str("message id (msg_...)")}, "id"),
			annotations(false, false, true, false), nil),
		s.tool("save_received_file", "Save a received file",
			"Save the file(s) offered in an inbox message into the user's drive, without re-downloading. "+
				"Single-use links are consumed by this.",
			obj(map[string]any{"message_id": str("inbox message id (msg_...)")}, "message_id"),
			annotations(false, false, true, false), nil),
		s.tool("delete_file", "Delete a file",
			"Permanently delete a file from the user's drive. Its live download links stop working. "+
				"Only do this when the user asks.",
			obj(map[string]any{"file": fileRefSchema()}, "file"),
			annotations(false, true, true, false), nil),
		s.tool("create_upload_request", "Get an upload page",
			"Create a one-time web page where a person can upload a file (any size the drive allows) straight into "+
				"the user's drive — useful when a file is too big to attach in chat.",
			obj(map[string]any{
				"note": str("what you want them to upload"),
				"ttl":  str(`how long the page works, like "24h"`),
			}),
			annotations(false, false, false, true), nil),
		s.tool("whoami", "Show account",
			"Show which AgentTransfer identity this AI is connected as: its address, the person it belongs to, "+
				"drive usage and limits.",
			obj(map[string]any{}),
			annotations(true, false, true, false), nil),
	}
	if s.cfg.AppDomain != "" {
		tools = append(tools,
			s.tool("app_status", "App status",
				"Get this agent's hosted app eligibility, public URL, status, active deployment, and storage usage.",
				obj(map[string]any{}), annotations(true, false, true, false), nil),
			s.tool("deploy_app_image", "Deploy an app image",
				"Deploy an OCI image as this verified agent's hosted app. Hosted HTTP MCP cannot read local paths or upload source/static bundles; for those, run the local stdio bridge and call deploy_app with a local path.",
				obj(map[string]any{
					"image":       str("OCI image reference (required)"),
					"port":        intp("container HTTP port (default 8080)"),
					"env":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "container environment variables; values are never returned"},
					"command":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "container argv override"},
					"health_path": str("HTTP health-check path inside the app (default /)"),
				}, "image"), annotations(false, true, false, true), nil),
			s.tool("app_logs", "App logs",
				"Read a bounded tail of this verified agent's container app logs.",
				obj(map[string]any{"tail": intp("recent lines, 1-2000 (default 200)")}), annotations(true, false, true, false), nil),
			s.tool("stop_app", "Stop app",
				"Stop this verified agent's running app without deleting its configuration or data.",
				obj(map[string]any{}), annotations(false, true, true, false), nil),
		)
	}
	return tools
}

const mcpInstructions = "AgentTransfer moves files between AI agents. The user has one drive shared by every AI " +
	"they connect (ChatGPT, Claude, Muse, coding agents): save_file puts a file in it, list_files/read_file find " +
	"and read it from any of them, get_link makes an expiring download link, and send delivers a file to " +
	"another agent or person by address (e.g. dana@agenttransfer.dev) with its sha256 so the recipient can " +
	"verify it. File bytes never pass through the chat unless you read a file. Supported transfer events emit " +
	"best-effort signed receipts."

// ---- connector tool implementations ----

func (s *Server) newFetchClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && !s.allowPrivateWebhooks {
				return errors.New("redirect to a non-https URL")
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
				Control: s.webhookDialControl, // public addresses only, checked at dial time
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// fetchInto streams an assistant-provided file URL (ChatGPT's file
// download_url) into the folder. The fetch is SSRF-guarded at dial time.
func (s *Server) fetchInto(ctx context.Context, agent store.Agent, rawURL, name, mimeType string) (*uploadResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !s.allowPrivateWebhooks) {
		return nil, errors.New("file download_url must be an https URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.newFetchClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch the attached file: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("fetch the attached file: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > s.cfg.MaxFileSize {
		return nil, fmt.Errorf("file is %d bytes; the limit is %d", resp.ContentLength, s.cfg.MaxFileSize)
	}
	if mimeType == "" {
		mimeType = resp.Header.Get("Content-Type")
	}
	if name == "" {
		name = "upload.bin"
	}
	res, _, err := s.performUpload(agent, name, mimeType, resp.Body, false, 0, false)
	return res, err
}

func (s *Server) mcpSaveFile(ctx context.Context, agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		File *struct {
			DownloadURL string `json:"download_url"`
			FileID      string `json:"file_id"`
			MIMEType    string `json:"mime_type"`
			FileName    string `json:"file_name"`
		} `json:"file"`
		Name          string `json:"name"`
		Content       string `json:"content"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	name := strings.TrimSpace(p.Name)
	var res *uploadResult
	var err error
	switch {
	case p.File != nil && p.File.DownloadURL != "":
		if name == "" {
			name = p.File.FileName
		}
		res, err = s.fetchInto(ctx, agent, p.File.DownloadURL, name, p.File.MIMEType)
	case p.Content != "" || p.ContentBase64 != "":
		if name == "" {
			return nil, errors.New(`name is required when saving content (e.g. "notes.md")`)
		}
		var data []byte
		if p.ContentBase64 != "" {
			data, err = base64.StdEncoding.DecodeString(p.ContentBase64)
			if err != nil {
				return nil, fmt.Errorf("bad content_base64: %v", err)
			}
		} else {
			data = []byte(p.Content)
		}
		if len(data) > inlineSaveMax {
			return nil, fmt.Errorf("inline content is capped at %d MiB; for bigger files use create_upload_request", inlineSaveMax>>20)
		}
		res, _, err = s.performUpload(agent, name, "", strings.NewReader(string(data)), false, 0, false)
	default:
		return nil, errors.New("nothing to save: attach a file, or pass name + content")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"saved": res.Name, "size": res.Size, "mime": res.MIME, "sha256": res.SHA256,
		"note": "saved to the user's AgentTransfer drive; every AI they've connected can now find it"}, nil
}

func (s *Server) mcpListFiles(agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	_ = json.Unmarshal(args, &p)
	if p.Limit <= 0 {
		p.Limit = 50
	}
	if p.Limit > 500 {
		p.Limit = 500
	}
	folder := s.folderFor(agent)
	files, err := s.st.ListFiles(folder.ID)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(p.Query))
	out := []map[string]any{}
	for _, f := range files {
		if q != "" && !strings.Contains(strings.ToLower(f.Name), q) {
			continue
		}
		e := map[string]any{"name": f.Name, "size": f.Size, "mime": f.MIME, "sha256": f.SHA256,
			"saved": time.Unix(f.CreatedAt, 0).UTC().Format(time.RFC3339)}
		if f.ExpiresAt > 0 {
			e["expires"] = time.Unix(f.ExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		if !f.Claimed {
			e["unclaimed"] = true
		}
		out = append(out, e)
		if len(out) >= p.Limit {
			break
		}
	}
	used, _ := s.st.StorageUsed(folder.ID)
	return map[string]any{"files": out, "count": len(out), "storage_used": used, "storage_quota": s.quotaFor(folder)}, nil
}

func isTextMIME(m string) bool {
	m = strings.ToLower(strings.TrimSpace(strings.Split(m, ";")[0]))
	if strings.HasPrefix(m, "text/") {
		return true
	}
	switch m {
	case "application/json", "application/xml", "application/x-yaml", "application/yaml", "application/javascript",
		"application/x-sh", "application/sql", "application/toml", "application/x-ndjson", "application/ld+json",
		"image/svg+xml", "application/csv":
		return true
	}
	return false
}

func (s *Server) mcpReadFile(ctx context.Context, agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	folder := s.folderFor(agent)
	f, err := s.resolveFile(folder, p.File)
	if err != nil {
		return nil, err
	}
	meta := map[string]any{"name": f.Name, "size": f.Size, "mime": f.MIME, "sha256": f.SHA256}
	isImage := strings.HasPrefix(f.MIME, "image/") && f.MIME != "image/svg+xml"
	if !isTextMIME(f.MIME) && !(isImage && f.Size <= readImageMax) && f.Size > 0 {
		// Peek: an unlabeled file may still be text.
		if !(f.MIME == "application/octet-stream" && f.Size <= int64(readTextMax)) {
			return s.readFileLink(folder, f, meta, "this file type can't be shown in chat; give the user the link to open it")
		}
	}
	limit := int64(readTextMax)
	if isImage {
		limit = readImageMax
	}
	r, _, err := s.st.BlobReader(ctx, f.SHA256)
	if err != nil {
		return nil, errors.New("file bytes are unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	r.Close()
	if err != nil {
		return nil, err
	}
	s.appendReceipt(agent.Email, receipt.ActionDownloaded, f.SHA256, int64(len(data)), "mcp:read", "")
	if isImage {
		return &mcpRich{
			content: []map[string]any{
				{"type": "image", "data": base64.StdEncoding.EncodeToString(data), "mimeType": f.MIME},
				{"type": "text", "text": fmt.Sprintf("%s (%s, %d bytes, sha256 %s)", f.Name, f.MIME, f.Size, f.SHA256)},
			},
			structured: meta,
		}, nil
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	if !utf8.Valid(data) && !truncated {
		return s.readFileLink(folder, f, meta, "this file is binary; give the user the link to open it")
	}
	text := strings.ToValidUTF8(string(data), "")
	meta["content"] = text
	if truncated {
		meta["truncated"] = true
		meta["note"] = fmt.Sprintf("showing the first %d characters of %d bytes", len(text), f.Size)
	}
	return &mcpRich{
		content:    []map[string]any{{"type": "text", "text": fmt.Sprintf("%s (%d bytes):\n\n%s", f.Name, f.Size, text)}},
		structured: meta,
	}, nil
}

func (s *Server) readFileLink(folder store.Agent, f store.File, meta map[string]any, note string) (any, error) {
	l, err := s.st.CreateLink(folder.ID, f.SHA256, f.Name, f.MIME, f.Size, false, time.Hour)
	if err != nil {
		return nil, err
	}
	meta["download_url"] = s.linkURL(l.Token)
	meta["link_expires"] = time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339)
	meta["note"] = note
	return meta, nil
}

func (s *Server) mcpGetLink(agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		File string `json:"file"`
		TTL  string `json:"ttl"`
		Once bool   `json:"once"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	folder := s.folderFor(agent)
	f, err := s.resolveFile(folder, p.File)
	if err != nil {
		return nil, err
	}
	ttl, err := s.ttlFrom(p.TTL, s.cfg.DefaultTTL)
	if err != nil {
		return nil, err
	}
	l, err := s.st.CreateLink(folder.ID, f.SHA256, f.Name, f.MIME, f.Size, p.Once, ttl)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"url": s.linkURL(l.Token), "name": l.Name, "size": l.Size, "sha256": l.SHA256,
		"expires": time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339), "single_use": l.Once}
	if s.linkNeedsAgent(l) {
		out["note"] = "this account isn't verified yet, so the link downloads only with an agent credential"
	}
	return out, nil
}

func (s *Server) mcpDeleteFile(agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	folder := s.folderFor(agent)
	f, err := s.resolveFile(folder, p.File)
	if err != nil {
		return nil, err
	}
	if _, err := s.st.DeleteFileEntry(folder.ID, f.SHA256, f.Name); err != nil {
		return nil, err
	}
	s.appendReceipt(agent.Email, receipt.ActionDeleted, f.SHA256, f.Size, "file:"+f.Name, "")
	revoked := 0
	if _, err := s.st.FileBySHA(folder.ID, f.SHA256); errors.Is(err, store.ErrNotFound) {
		// No other name holds these bytes: their links die with the file.
		links, _ := s.st.RevokeLinksForSHA(folder.ID, f.SHA256)
		for _, l := range links {
			s.sever(l.Token)
			s.appendReceipt(agent.Email, receipt.ActionRevoked, l.SHA256, l.Size, "link:"+l.Token, "")
		}
		revoked = len(links)
	}
	return map[string]any{"deleted": f.Name, "links_revoked": revoked}, nil
}

// mcpSaveReceived files an inbox offer's bytes into the drive by reference —
// the blob already exists on this instance, so nothing is downloaded.
func (s *Server) mcpSaveReceived(agent store.Agent, args json.RawMessage) (any, error) {
	var p struct {
		MessageID string `json:"message_id"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	m, err := s.st.GetMessage(agent.ID, strings.TrimSpace(p.MessageID))
	if err != nil {
		return nil, errors.New("no such message in this inbox")
	}
	folder := s.folderFor(agent)
	var saved []map[string]any
	var skipped []string
	if m.Manifest != "" {
		var man proto.Manifest
		if err := json.Unmarshal([]byte(m.Manifest), &man); err == nil {
			for _, part := range man.Parts {
				if part.File == nil {
					continue
				}
				token, ok := strings.CutPrefix(part.File.URI, s.BaseURL()+"/f/")
				if !ok {
					skipped = append(skipped, part.File.Name+" (on another instance: download it from "+part.File.URI+")")
					continue
				}
				token, _, _ = strings.Cut(token, "?")
				l, err := s.st.GetLink(token)
				if err != nil || l.Status != "active" || l.ExpiresAt <= time.Now().Unix() {
					skipped = append(skipped, part.File.Name+" (link expired)")
					continue
				}
				if l.Once {
					if _, err := s.st.BurnLink(l.Token); err != nil {
						skipped = append(skipped, part.File.Name+" (single-use link already used)")
						continue
					}
					s.appendReceipt(s.agentEmailByID(l.AgentID), receipt.ActionBurned, l.SHA256, l.Size, "link:"+l.Token, "")
				}
				f, err := s.fileIntoFolder(folder, l.SHA256, l.Name, l.MIME, l.Size, "inbound")
				if err != nil {
					skipped = append(skipped, part.File.Name+" ("+err.Error()+")")
					continue
				}
				s.appendReceipt(agent.Email, receipt.ActionReceived, l.SHA256, l.Size, "link:"+l.Token, m.MessageID)
				saved = append(saved, map[string]any{"name": f.Name, "size": f.Size, "sha256": f.SHA256})
			}
		}
	}
	for _, a := range m.Attachments {
		if f, err := s.st.KeepFile(folder.ID, a.SHA256, 0); err == nil {
			saved = append(saved, map[string]any{"name": f.Name, "size": f.Size, "sha256": f.SHA256})
		}
	}
	if len(saved) == 0 && len(skipped) == 0 {
		return nil, errors.New("that message has no files")
	}
	return map[string]any{"saved": saved, "skipped": skipped}, nil
}

// fileIntoFolder adds an existing blob to a folder under the folder's quota.
func (s *Server) fileIntoFolder(folder store.Agent, sha, name, mimeType string, size int64, source string) (store.File, error) {
	lock := s.uploadLock(folder.ID)
	lock.Lock()
	defer lock.Unlock()
	used, err := s.st.StorageUsed(folder.ID)
	if err != nil {
		return store.File{}, err
	}
	charged, err := s.st.AgentUsesStorageBlob(folder.ID, sha)
	if err != nil {
		return store.File{}, err
	}
	if !charged && !storageAdditionFits(used, size, s.quotaFor(folder)) {
		return store.File{}, errors.New("storage quota exceeded")
	}
	return s.st.AddFile(folder.ID, sha, name, mimeType, size, source, true, s.fileExpiry(folder))
}
