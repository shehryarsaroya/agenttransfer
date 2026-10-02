package server

import "net/http"

// handleOpenAPI serves an OpenAPI 3.1 description of the core REST API — the
// file and messaging surface an agent with its own computer (Meta Muse
// custom connectors, scripts, coding agents) needs. Admin, app-hosting and
// federation endpoints are documented in docs/api.md instead.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	base := s.BaseURL()
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	integer := func(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
	boolean := func(desc string) map[string]any { return map[string]any{"type": "boolean", "description": desc} }
	object := func(props map[string]any, required ...string) map[string]any {
		o := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			o["required"] = required
		}
		return o
	}
	jsonBody := func(schema map[string]any) map[string]any {
		return map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
	}
	ok := func(desc string) map[string]any {
		return map[string]any{"200": map[string]any{"description": desc, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}}
	}
	created := func(desc string) map[string]any {
		return map[string]any{"201": map[string]any{"description": desc, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}}
	}
	pathParam := func(name, desc string) map[string]any {
		return map[string]any{"name": name, "in": "path", "required": true, "schema": map[string]any{"type": "string"}, "description": desc}
	}
	op := func(id, summary, desc string, extra map[string]any) map[string]any {
		o := map[string]any{"operationId": id, "summary": summary, "description": desc}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	spec := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "AgentTransfer API",
			"version": Version,
			"description": "Move files between AI agents. Every agent has an address (handle+name@" + s.st.Instance() +
				") and shares its person's drive. Upload with a session (POST /v1/uploads, PUT the bytes to put_url, " +
				"POST complete), list and download files, mint expiring links, send files to any address, and read the inbox. " +
				"Authenticate with Authorization: Bearer <api key> (create one in your account) or an OAuth access token.",
		},
		"servers": []map[string]any{{"url": base}},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearer": map[string]any{"type": "http", "scheme": "bearer", "description": "API key (at_live_…) or OAuth access token"},
			},
		},
		"security": []map[string]any{{"bearer": []string{}}},
		"paths": map[string]any{
			"/v1/whoami": map[string]any{"get": op("whoami", "Who am I", "This agent's address, person, drive usage and limits.", map[string]any{"responses": ok("identity")})},
			"/v1/files": map[string]any{
				"get": op("listFiles", "List files", "Files in the drive, newest first, with name, size, mime, sha256.", map[string]any{"responses": ok("files")}),
			},
			"/v1/files/{name}": map[string]any{
				"put": op("putFile", "Upload a small file", "Stream raw bytes as the request body (up to 100 MB through this endpoint). For larger files use /v1/uploads.",
					map[string]any{"parameters": []any{pathParam("name", "file name")},
						"requestBody": map[string]any{"required": true, "content": map[string]any{"application/octet-stream": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}},
						"responses":   created("saved file (sha256, name, size)")}),
			},
			"/v1/files/{sha256}/content": map[string]any{
				"get": op("downloadFile", "Download a file", "Redirects to a short-lived download URL (X-Sha256 header carries the hash to verify).",
					map[string]any{"parameters": []any{pathParam("sha256", "the file's sha256")}, "responses": map[string]any{"302": map[string]any{"description": "redirect to the bytes"}, "200": map[string]any{"description": "the bytes"}}}),
			},
			"/v1/files/{sha256}": map[string]any{
				"delete": op("deleteFile", "Delete a file", "Delete a file (all names holding these bytes, or one with ?entry=<name>) and revoke its links.",
					map[string]any{"parameters": []any{pathParam("sha256", "the file's sha256"), map[string]any{"name": "entry", "in": "query", "schema": map[string]any{"type": "string"}, "description": "delete only this name"}}, "responses": ok("deleted")}),
			},
			"/v1/uploads": map[string]any{
				"post": op("createUpload", "Start an upload", "Returns put_url (one PUT of the whole file) or, for large files, part_urls for a resumable multipart upload. Then call complete.",
					map[string]any{"requestBody": jsonBody(object(map[string]any{
						"name": str("file name"), "size": integer("exact size in bytes"), "mime": str("content type (optional)"),
						"sha256": str("optional: the file's sha256; the upload is rejected if the bytes don't match"),
					}, "name", "size")), "responses": created("upload session")}),
			},
			"/v1/uploads/{upload_id}/complete": map[string]any{
				"post": op("completeUpload", "Finish an upload", "Verifies the bytes' sha256 and adds the file to the drive. For multipart uploads you may pass {\"parts\":[{\"part_number\":1,\"etag\":\"…\"}]} or omit it.",
					map[string]any{"parameters": []any{pathParam("upload_id", "from createUpload")}, "responses": created("the saved file")}),
			},
			"/v1/uploads/{upload_id}": map[string]any{
				"get": op("getUpload", "Upload status", "Status, uploaded parts (to resume), or a fresh put_url.",
					map[string]any{"parameters": []any{pathParam("upload_id", "from createUpload")}, "responses": ok("status")}),
			},
			"/v1/links": map[string]any{
				"post": op("createLink", "Create a download link", "An expiring URL anyone can download from (max 24h; once=true for single use).",
					map[string]any{"requestBody": jsonBody(object(map[string]any{
						"file": str(`a file name in the drive, or "sha256:<hash>"`), "ttl": str(`e.g. "3h"`), "once": boolean("single download"),
					}, "file")), "responses": created("link with url and expires_at")}),
			},
			"/v1/send": map[string]any{
				"post": op("send", "Send a file or note", "Deliver to agents or people by address; recipients get a sha256-verified offer. Send an Idempotency-Key header to make retries safe.",
					map[string]any{"requestBody": jsonBody(object(map[string]any{
						"to":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "addresses, e.g. dana@" + s.st.Instance()},
						"file": str(`a file in the drive (name or "sha256:<hash>")`), "note": str("message text"), "ttl": str("link lifetime"),
					}, "to")), "responses": ok("delivery report")}),
			},
			"/v1/inbox": map[string]any{
				"get": op("listInbox", "List inbox", "Messages and file offers sent to this agent (?unread=1 for unread only).", map[string]any{"responses": ok("messages")}),
			},
			"/v1/inbox/wait": map[string]any{
				"get": op("waitInbox", "Wait for a message", "Long-polls until something arrives (?timeout=seconds, max 60).",
					map[string]any{"parameters": []any{map[string]any{"name": "timeout", "in": "query", "schema": map[string]any{"type": "integer"}}}, "responses": ok("messages")}),
			},
			"/v1/inbox/{id}": map[string]any{
				"get": op("getMessage", "Read a message", "One message with its file offers (name, size, sha256, url).",
					map[string]any{"parameters": []any{pathParam("id", "message id")}, "responses": ok("message")}),
			},
		},
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, spec)
}
