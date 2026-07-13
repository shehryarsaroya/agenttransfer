package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// handleShare serves /f/{token}: an HTML page for browsers, raw bytes for
// everything else.
//
// Burn-after-read semantics, precisely:
//   - The HTML page and HEAD requests NEVER consume the read (link unfurlers
//     are harmless).
//   - Only a byte-stream that completes burns the link.
//   - Burn links are single-flight: one active download; concurrent requests
//     get 409, later ones 410.
//   - Range requests on burn links are answered with the full body so
//     "complete" stays unambiguous.
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	// Link state (expiry, revoke, burn-after-read) is authoritative only at
	// this process. An intermediary replaying a cached page or byte response
	// would bypass those semantics, so public share URLs are never cacheable.
	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	token := r.PathValue("token")
	l, err := s.st.GetLink(token)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if l.Status != "active" || l.ExpiresAt <= time.Now().Unix() {
		s.goneLink(w, l)
		return
	}

	q := r.URL.Query()
	wantsDownload := q.Get("dl") == "1" || q.Get("dl") == "true" ||
		strings.Contains(r.Header.Get("Accept"), "application/octet-stream")
	wantsPage := !wantsDownload && strings.Contains(r.Header.Get("Accept"), "text/html")

	// Burn links only stream on an EXPLICIT download signal (?dl=1 or an
	// octet-stream Accept). Ambiguous GETs (Accept: */* — email security
	// scanners, link prefetchers) get the page, not the burn.
	if l.Once && !wantsDownload {
		wantsPage = true
	}

	if r.Method == http.MethodHead {
		s.shareHeaders(w, l)
		return
	}
	if wantsPage {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = s.tmpl.ExecuteTemplate(w, "share.html", map[string]any{
			"Name":      l.Name,
			"Size":      humanSize(l.Size),
			"SHA256":    l.SHA256,
			"Once":      l.Once,
			"ExpiresAt": time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339),
			"ExpiresIn": time.Until(time.Unix(l.ExpiresAt, 0)).Round(time.Second).String(),
			"URL":       s.linkURL(l.Token) + "?dl=1",
		})
		return
	}

	if l.Once {
		s.streamBurn(w, r, l)
		return
	}
	s.streamNormal(w, r, l)
}

func (s *Server) shareHeaders(w http.ResponseWriter, l store.Link) {
	w.Header().Set("Content-Type", l.MIME)
	w.Header().Set("Content-Length", strconv.FormatInt(l.Size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", l.Name))
	w.Header().Set("X-Sha256", l.SHA256)
	w.Header().Set("X-Expires-At", time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339))
}

func (s *Server) goneLink(w http.ResponseWriter, l store.Link) {
	status := l.Status
	if status == "active" {
		status = "expired"
	}
	http.Error(w, "this link is "+status+" — AgentTransfer share links are ephemeral", http.StatusGone)
}

// severReader aborts an in-flight stream when its link gets revoked, and
// remembers that it did so the caller can skip download accounting.
type severReader struct {
	io.ReadSeeker
	s       *Server
	token   string
	severed bool
}

func (r *severReader) Read(p []byte) (int, error) {
	if r.s.isSevered(r.token) {
		r.severed = true
		return 0, errors.New("link revoked mid-stream")
	}
	return r.ReadSeeker.Read(p)
}

func (s *Server) streamNormal(w http.ResponseWriter, r *http.Request, l store.Link) {
	blob, err := s.st.OpenBlob(l.SHA256)
	if err != nil {
		http.Error(w, "blob missing", http.StatusInternalServerError)
		return
	}
	defer blob.Close()
	w.Header().Set("Content-Type", l.MIME)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", l.Name))
	w.Header().Set("X-Sha256", l.SHA256)
	sr := &severReader{ReadSeeker: blob, s: s, token: l.Token}
	http.ServeContent(w, r, l.Name, time.Unix(l.CreatedAt, 0), sr)
	if sr.severed {
		return // revoked mid-stream: not a download, and the revoker receipted it
	}
	// Counted after serving; a partial range fetch still counts as one
	// download event.
	_ = s.st.CountDownload(l.Token)
	s.metrics.downloads.Add(1)
	actor := s.agentEmailByID(l.AgentID)
	_, _ = s.st.AppendReceipt(actor, receipt.ActionDownloaded, l.SHA256, l.Size, "link:"+l.Token, "")
}

func (s *Server) streamBurn(w http.ResponseWriter, r *http.Request, l store.Link) {
	// Single flight: only one active download may attempt the burn.
	s.burnMu.Lock()
	if s.burning[l.Token] {
		s.burnMu.Unlock()
		http.Error(w, "a download of this single-use link is already in progress", http.StatusConflict)
		return
	}
	s.burning[l.Token] = true
	s.burnMu.Unlock()
	defer func() {
		s.burnMu.Lock()
		delete(s.burning, l.Token)
		s.burnMu.Unlock()
	}()

	// Re-check under the flight lock: it may have burned since the lookup.
	l2, err := s.st.GetLink(l.Token)
	if err != nil || l2.Status != "active" || l2.ExpiresAt <= time.Now().Unix() {
		s.goneLink(w, l2)
		return
	}

	blob, err := s.st.OpenBlob(l.SHA256)
	if err != nil {
		http.Error(w, "blob missing", http.StatusInternalServerError)
		return
	}
	defer blob.Close()

	s.shareHeaders(w, l)
	w.WriteHeader(http.StatusOK) // full body always; no ranges on burn links

	buf := make([]byte, 1<<20)
	var written int64
	for {
		if s.isSevered(l.Token) {
			return // revoked mid-stream: cut the connection, no burn state change (already revoked)
		}
		n, rerr := blob.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // client went away before completion: link survives
			}
			written += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return
		}
	}
	if written != l.Size {
		return
	}

	// Completed: burn it.
	if _, err := s.st.BurnLink(l.Token); err == nil {
		_ = s.st.CountDownload(l.Token)
		s.metrics.downloads.Add(1)
		actor := s.agentEmailByID(l.AgentID)
		_, _ = s.st.AppendReceipt(actor, receipt.ActionDownloaded, l.SHA256, l.Size, "link:"+l.Token, "")
		_, _ = s.st.AppendReceipt(actor, receipt.ActionBurned, l.SHA256, l.Size, "link:"+l.Token, "")
	}
}

// ---- human upload pages (/u/{token}) ----

func (s *Server) handleUploadPage(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.GetUploadRequest(r.PathValue("token"))
	if err != nil {
		http.Error(w, "this upload link is invalid, used, or expired", http.StatusNotFound)
		return
	}
	agent, _ := s.st.AgentByID(u.AgentID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "upload.html", map[string]any{
		"Note":    u.Note,
		"Agent":   agent.Email,
		"Token":   u.Token,
		"MaxSize": humanSize(s.cfg.MaxFileSize),
	})
}

func (s *Server) handleUploadSubmit(w http.ResponseWriter, r *http.Request) {
	// Same slow-body deadline as API uploads — a browser has even less
	// excuse to trickle a multipart body for an hour.
	if d := s.cfg.UploadBodyTimeout; d > 0 {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(d))
	}
	token := r.PathValue("token")
	u, err := s.st.GetUploadRequest(token)
	if err != nil {
		http.Error(w, "this upload link is invalid, used, or expired", http.StatusNotFound)
		return
	}
	// Global disk guard — checked before the one-time token is consumed, so
	// the page stays usable once space frees up.
	if s.diskFull() {
		http.Error(w, "this instance is out of storage right now — the link is still valid, try again later", http.StatusInsufficientStorage)
		return
	}
	agent, err := s.st.AgentByID(u.AgentID)
	if err != nil {
		http.Error(w, "agent missing", http.StatusInternalServerError)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart/form-data with a \"file\" field", http.StatusBadRequest)
		return
	}
	var part io.Reader
	var name, ctype string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "bad multipart body", http.StatusBadRequest)
			return
		}
		if p.FormName() == "file" && p.FileName() != "" {
			part, name, ctype = p, p.FileName(), p.Header.Get("Content-Type")
			break
		}
	}
	if part == nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}

	// Store and validate BEFORE consuming the one-time token: a rejected
	// upload (too big, over quota) must not burn the page. A failed store
	// leaves at most an unreferenced blob for the janitor.
	sha, size, err := s.st.PutBlob(part, s.cfg.MaxFileSize)
	if err != nil {
		if errors.Is(err, store.ErrDiskReserve) {
			http.Error(w, "instance storage reserve reached — the link is still valid, try later", http.StatusInsufficientStorage)
			return
		}
		if errors.Is(err, store.ErrQuota) {
			http.Error(w, "file exceeds the size limit — the link is still valid, try a smaller file", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	lock := s.uploadLock(agent.ID)
	lock.Lock()
	used, _ := s.st.StorageUsed(agent.ID)
	if !s.st.AgentHasFile(agent.ID, sha, name) && used+size > s.quotaFor(agent) {
		lock.Unlock()
		http.Error(w, "the agent's storage quota is exhausted", http.StatusInsufficientStorage)
		return
	}

	// Now consume the one-time token; the winner's file goes through.
	won, err := s.st.UseUploadRequest(token)
	if err != nil || !won {
		lock.Unlock()
		http.Error(w, "this upload link was just used", http.StatusConflict)
		return
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}

	// Arrives unclaimed: the agent keeps it or it expires with DEFAULT_TTL.
	expires := time.Now().Add(s.cfg.DefaultTTL).Unix()
	f, err := s.st.AddFile(agent.ID, sha, name, ctype, size, "request", false, expires)
	lock.Unlock()
	if err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	subject := "File dropped: " + f.Name
	if u.Note != "" {
		subject = u.Note
	}
	dropMsg, _ := s.st.AddMessage(store.Message{
		AgentID: agent.ID,
		From:    "upload-request@" + s.st.Instance(),
		To:      []string{agent.Email},
		Subject: subject,
		Text: fmt.Sprintf("A file arrived via your upload request.\n\nname: %s\nsize: %d\nsha256: %s\n\n"+
			"It is unclaimed and expires at %s unless you keep it:\nPOST /v1/files/%s/keep",
			f.Name, size, sha, time.Unix(expires, 0).UTC().Format(time.RFC3339), sha),
		Attachments: []store.Attachment{{SHA256: sha, Name: f.Name, MIME: ctype, Size: size}},
		DKIM:        "local", SPF: "local",
	})
	s.hub.notify(agent.ID)
	s.enqueueWebhooks(agent.ID, "message.received", dropMsg.ID, "upload-request@"+s.st.Instance())
	s.metrics.uploads.Add(1)
	_, _ = s.st.AppendReceipt(agent.Email, receipt.ActionReceived, sha, size, "upload-request:"+token, "")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "uploaded.html", map[string]any{
		"Name":  f.Name,
		"Size":  humanSize(size),
		"SHA":   sha,
		"Agent": agent.Email,
	})
}
