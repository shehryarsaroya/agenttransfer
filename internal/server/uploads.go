package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/s3"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// Direct uploads: in bucket mode a client asks for an upload session, sends
// the bytes straight to object storage over presigned URLs, then calls
// complete. The server re-reads the object and hashes it before anything
// lands in a folder, so content addressing and quota accounting hold exactly
// as for uploads that stream through the server — while multi-gigabyte bodies
// never touch the control plane or its proxy's request-size cap.
// Upload size thresholds (variables so tests can exercise multipart small).
var (
	singlePutMax  int64 = 64 << 20  // one presigned PUT up to this size
	minPartSize   int64 = 16 << 20  // multipart part size floor
	syncVerifyMax int64 = 256 << 20 // larger objects verify in the background
)

const (
	maxUploadParts     = 10000 // S3/R2 multipart limit
	uploadSessionTTL   = 24 * time.Hour
	presignedUploadTTL = time.Hour
	maxActiveUploads   = 20
	maxPartURLsPerCall = 200
)

func partSizeFor(size int64) int64 {
	ps := minPartSize
	if need := (size + maxUploadParts - 1) / maxUploadParts; need > ps {
		ps = (need + (1<<20 - 1)) &^ (1<<20 - 1) // round up to a MiB
	}
	return ps
}

func validSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func guessMIME(name, given string) string {
	if given != "" && given != "application/octet-stream" && !strings.HasPrefix(given, "multipart/") {
		return given
	}
	if m := mime.TypeByExtension(filepath.Ext(name)); m != "" {
		return m
	}
	return "application/octet-stream"
}

func (s *Server) uploadView(u store.UploadSession) map[string]any {
	out := map[string]any{
		"upload_id":    u.ID,
		"status":       u.Status,
		"name":         u.Name,
		"size":         u.Size,
		"mode":         "single",
		"expires_at":   time.Unix(u.ExpiresAt, 0).UTC().Format(time.RFC3339),
		"complete_url": s.BaseURL() + "/v1/uploads/" + u.ID + "/complete",
	}
	if u.Multipart() {
		out["mode"] = "multipart"
		out["part_size"] = u.PartSize
		out["parts"] = u.Parts()
		out["parts_url"] = s.BaseURL() + "/v1/uploads/" + u.ID + "/parts"
	}
	if u.SHA256 != "" {
		out["sha256"] = u.SHA256
	}
	if u.Error != "" {
		out["error"] = u.Error
	}
	return out
}

// handleCreateUpload (POST /v1/uploads) opens a direct-to-bucket session.
func (s *Server) handleCreateUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	if !s.st.Remote() {
		errJSON(w, http.StatusNotImplemented, "direct uploads need object storage on this instance; PUT the bytes to /v1/files/{name}")
		return
	}
	var req struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		MIME   string `json:"mime"`
		SHA256 string `json:"sha256"`
		Share  bool   `json:"share"`
		TTL    string `json:"ttl"`
		Once   bool   `json:"once"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		errJSON(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Size < 0 || req.Size > s.cfg.MaxFileSize {
		errJSON(w, http.StatusRequestEntityTooLarge, "size must be between 0 and %d bytes", s.cfg.MaxFileSize)
		return
	}
	req.SHA256 = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.SHA256)), "sha256:")
	if req.SHA256 != "" && !validSHA256Hex(req.SHA256) {
		errJSON(w, http.StatusBadRequest, "sha256 must be 64 lowercase hex characters")
		return
	}
	ttl, err := s.ttlFrom(req.TTL, s.cfg.DefaultTTL)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := s.checkRate(agent.ID, "uploads", s.cfg.UploadRate); err != nil {
		errJSON(w, http.StatusTooManyRequests, "%v", err)
		return
	}
	folder := s.folderFor(agent)
	mimeType := guessMIME(req.Name, req.MIME)

	lock := s.uploadLock(folder.ID)
	lock.Lock()
	// Instant upload: the content is already in this folder, so recording a
	// second name grants no new access (the hash alone never unlocks bytes the
	// caller doesn't already hold).
	if req.SHA256 != "" {
		if have, _ := s.st.AgentUsesStorageBlob(folder.ID, req.SHA256); have {
			if existing, err := s.st.FileBySHA(folder.ID, req.SHA256); err == nil && existing.Size == req.Size {
				f, err := s.st.AddFile(folder.ID, req.SHA256, req.Name, mimeType, req.Size, "upload", true, s.fileExpiry(folder))
				lock.Unlock()
				if err != nil {
					errJSON(w, http.StatusInternalServerError, "%v", err)
					return
				}
				res := s.uploadResultFor(agent, folder, f, req.Share, ttl, req.Once)
				writeJSON(w, http.StatusCreated, map[string]any{"status": store.UploadDone, "deduplicated": true, "file": res})
				return
			}
		}
	}
	active, err := s.st.CountActiveUploads(folder.ID)
	if err == nil && active >= maxActiveUploads {
		lock.Unlock()
		errJSON(w, http.StatusTooManyRequests, "too many uploads in progress (max %d); complete or cancel some first", maxActiveUploads)
		return
	}
	used, err := s.st.StorageUsed(folder.ID)
	if err != nil {
		lock.Unlock()
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	pending, _ := s.st.PendingUploadBytes(folder.ID)
	if quota := s.quotaFor(folder); !storageAdditionFits(used+pending, req.Size, quota) {
		lock.Unlock()
		errJSON(w, http.StatusRequestEntityTooLarge, "storage quota exceeded: %d used + %d in flight + %d new > %d", used, pending, req.Size, quota)
		return
	}
	key := "o/" + strings.TrimPrefix(store.NewID("u"), "u_")
	sess := store.UploadSession{
		FolderID: folder.ID, ActorID: agent.ID, Name: req.Name, MIME: mimeType, Size: req.Size,
		DeclaredSHA256: req.SHA256, ObjectKey: key, Share: req.Share, TTLSeconds: int64(ttl / time.Second),
		Once: req.Once, ExpiresAt: time.Now().Add(uploadSessionTTL).Unix(),
	}
	if req.Size > singlePutMax {
		id, err := s.st.RemoteClient().CreateMultipartUpload(r.Context(), key, mimeType)
		if err != nil {
			lock.Unlock()
			errJSON(w, http.StatusBadGateway, "object storage: %v", err)
			return
		}
		sess.S3UploadID = id
		sess.PartSize = partSizeFor(req.Size)
	}
	sess, err = s.st.CreateUploadSession(sess)
	lock.Unlock()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := s.uploadView(sess)
	if sess.Multipart() {
		n := sess.Parts()
		if n > maxPartURLsPerCall {
			n = maxPartURLsPerCall
		}
		urls, err := s.partURLs(sess, 1, n)
		if err != nil {
			errJSON(w, http.StatusBadGateway, "%v", err)
			return
		}
		out["part_urls"] = urls
	} else {
		u, err := s.st.RemoteClient().PresignPut(sess.ObjectKey, presignedUploadTTL)
		if err != nil {
			errJSON(w, http.StatusBadGateway, "%v", err)
			return
		}
		out["put_url"] = u
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) partURLs(u store.UploadSession, from, to int) ([]map[string]any, error) {
	var out []map[string]any
	for n := from; n <= to; n++ {
		url, err := s.st.RemoteClient().PresignUploadPart(u.ObjectKey, u.S3UploadID, n, presignedUploadTTL)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"part_number": n, "url": url})
	}
	return out, nil
}

// ownUpload loads a session the caller may act on (same folder).
func (s *Server) ownUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) (store.UploadSession, bool) {
	u, err := s.st.GetUploadSession(r.PathValue("id"))
	if err != nil || u.FolderID != s.folderFor(agent).ID {
		errJSON(w, http.StatusNotFound, "no such upload")
		return u, false
	}
	return u, true
}

// handleUploadParts (POST /v1/uploads/{id}/parts) presigns more part URLs.
func (s *Server) handleUploadParts(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	u, ok := s.ownUpload(w, r, agent)
	if !ok {
		return
	}
	if !u.Multipart() || u.Status != store.UploadPending {
		errJSON(w, http.StatusConflict, "upload is not an open multipart upload")
		return
	}
	var req struct {
		PartNumbers []int `json:"part_numbers"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(req.PartNumbers) == 0 || len(req.PartNumbers) > maxPartURLsPerCall {
		errJSON(w, http.StatusBadRequest, "part_numbers must list 1-%d parts", maxPartURLsPerCall)
		return
	}
	var out []map[string]any
	for _, n := range req.PartNumbers {
		if n < 1 || n > u.Parts() {
			errJSON(w, http.StatusBadRequest, "part %d out of range 1-%d", n, u.Parts())
			return
		}
		urls, err := s.partURLs(u, n, n)
		if err != nil {
			errJSON(w, http.StatusBadGateway, "%v", err)
			return
		}
		out = append(out, urls...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"part_urls": out})
}

// handleGetUpload (GET /v1/uploads/{id}) reports status, and for an open
// multipart upload the parts already stored (so a client can resume).
func (s *Server) handleGetUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	u, ok := s.ownUpload(w, r, agent)
	if !ok {
		return
	}
	out := s.uploadView(u)
	if u.Status == store.UploadPending {
		if u.Multipart() {
			if parts, err := s.st.RemoteClient().ListParts(r.Context(), u.ObjectKey, u.S3UploadID); err == nil {
				out["uploaded_parts"] = parts
			}
		} else if put, err := s.st.RemoteClient().PresignPut(u.ObjectKey, presignedUploadTTL); err == nil {
			out["put_url"] = put // a fresh URL, for resuming after the first one expired
		}
	}
	if u.Status == store.UploadDone {
		if f, err := s.st.FileEntry(u.FolderID, u.SHA256, u.Name); err == nil {
			out["file"] = map[string]any{"sha256": f.SHA256, "name": f.Name, "mime": f.MIME, "size": f.Size}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCancelUpload (DELETE /v1/uploads/{id}) abandons an open upload.
func (s *Server) handleCancelUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	u, ok := s.ownUpload(w, r, agent)
	if !ok {
		return
	}
	won, _ := s.st.TransitionUpload(u.ID, store.UploadPending, store.UploadExpired, "canceled", "")
	if !won {
		errJSON(w, http.StatusConflict, "upload is %s", u.Status)
		return
	}
	s.discardUploadObject(u)
	writeJSON(w, http.StatusOK, map[string]any{"upload_id": u.ID, "status": store.UploadExpired})
}

func (s *Server) discardUploadObject(u store.UploadSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if u.Multipart() {
		_ = s.st.RemoteClient().AbortMultipartUpload(ctx, u.ObjectKey, u.S3UploadID)
	}
	if err := s.st.RemoteClient().DeleteObject(ctx, u.ObjectKey); err != nil {
		s.st.TombObject(u.ObjectKey)
	}
}

// handleCompleteUpload (POST /v1/uploads/{id}/complete) assembles the object
// (multipart), checks its size, and verifies its hash — synchronously for
// small objects, in the background (202) for large ones.
func (s *Server) handleCompleteUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	u, ok := s.ownUpload(w, r, agent)
	if !ok {
		return
	}
	switch u.Status {
	case store.UploadDone, store.UploadVerifying:
		writeJSON(w, http.StatusOK, s.uploadView(u))
		return
	case store.UploadPending:
	default:
		errJSON(w, http.StatusConflict, "upload is %s: %s", u.Status, u.Error)
		return
	}
	var req struct {
		Parts []s3.Part `json:"parts"`
	}
	if r.ContentLength != 0 {
		if err := decodeBody(r, &req); err != nil {
			errJSON(w, http.StatusBadRequest, "%v", err)
			return
		}
	}
	ctx := r.Context()
	rc := s.st.RemoteClient()
	if u.Multipart() {
		parts := req.Parts
		if len(parts) == 0 {
			// Clients that didn't keep ETags can let the server read them back.
			listed, err := rc.ListParts(ctx, u.ObjectKey, u.S3UploadID)
			if err != nil {
				errJSON(w, http.StatusBadGateway, "list parts: %v", err)
				return
			}
			for _, p := range listed {
				parts = append(parts, s3.Part{Number: p.Number, ETag: p.ETag})
			}
		}
		if len(parts) != u.Parts() {
			errJSON(w, http.StatusBadRequest, "expected %d parts, have %d — upload the missing parts (GET /v1/uploads/%s lists what's stored)", u.Parts(), len(parts), u.ID)
			return
		}
		if err := rc.CompleteMultipartUpload(ctx, u.ObjectKey, u.S3UploadID, parts); err != nil {
			errJSON(w, http.StatusBadRequest, "assemble upload: %v", err)
			return
		}
	}
	info, err := rc.HeadObject(ctx, u.ObjectKey)
	if errors.Is(err, s3.ErrNotFound) {
		errJSON(w, http.StatusBadRequest, "no bytes received yet — PUT the file to put_url first")
		return
	}
	if err != nil {
		errJSON(w, http.StatusBadGateway, "object storage: %v", err)
		return
	}
	if info.Size != u.Size {
		if won, _ := s.st.TransitionUpload(u.ID, store.UploadPending, store.UploadFailed,
			fmt.Sprintf("received %d bytes, declared %d", info.Size, u.Size), ""); won {
			s.discardUploadObject(u)
		}
		errJSON(w, http.StatusBadRequest, "received %d bytes but the upload declared %d — start a new upload", info.Size, u.Size)
		return
	}
	if won, _ := s.st.TransitionUpload(u.ID, store.UploadPending, store.UploadVerifying, "", ""); !won {
		cur, _ := s.st.GetUploadSession(u.ID)
		writeJSON(w, http.StatusOK, s.uploadView(cur))
		return
	}
	if u.Size > syncVerifyMax {
		go func() {
			if _, _, err := s.finishUpload(context.Background(), agent, u); err != nil {
				log.Printf("upload %s: %v", u.ID, err)
			}
		}()
		u.Status = store.UploadVerifying
		writeJSON(w, http.StatusAccepted, s.uploadView(u))
		return
	}
	res, status, err := s.finishUpload(ctx, agent, u)
	if err != nil {
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"upload_id": u.ID, "status": store.UploadDone, "file": res})
}

// finishUpload hashes the stored object, enforces the declared hash and the
// folder quota, records the blob (deduplicating), and files it.
func (s *Server) finishUpload(ctx context.Context, agent store.Agent, u store.UploadSession) (*uploadResult, int, error) {
	fail := func(status int, msg string) (*uploadResult, int, error) {
		if won, _ := s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadFailed, msg, ""); won {
			s.discardUploadObject(u)
		}
		return nil, status, errors.New(msg)
	}
	body, _, err := s.st.RemoteClient().GetObject(ctx, u.ObjectKey, "")
	if err != nil {
		_, _ = s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadPending, "", "")
		return nil, http.StatusBadGateway, fmt.Errorf("read back object: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, body)
	body.Close()
	if err != nil {
		_, _ = s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadPending, "", "")
		return nil, http.StatusBadGateway, fmt.Errorf("read back object: %w", err)
	}
	if n != u.Size {
		return fail(http.StatusBadRequest, fmt.Sprintf("object holds %d bytes, declared %d", n, u.Size))
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if u.DeclaredSHA256 != "" && sha != u.DeclaredSHA256 {
		return fail(http.StatusBadRequest, fmt.Sprintf("sha256 mismatch: declared %s, received %s", u.DeclaredSHA256, sha))
	}
	folder, err := s.st.AgentByID(u.FolderID)
	if err != nil {
		return fail(http.StatusGone, "the destination folder no longer exists")
	}
	lock := s.uploadLock(folder.ID)
	lock.Lock()
	if err := s.st.RecordRemoteObject(sha, u.Size, u.ObjectKey); err != nil {
		lock.Unlock()
		_, _ = s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadPending, "", "")
		return nil, http.StatusInternalServerError, err
	}
	used, err := s.st.StorageUsed(folder.ID)
	if err != nil {
		lock.Unlock()
		return nil, http.StatusInternalServerError, err
	}
	pending, _ := s.st.PendingUploadBytes(folder.ID)
	pending -= u.Size // this session is still counted as in flight
	alreadyCharged, _ := s.st.AgentUsesStorageBlob(folder.ID, sha)
	if !alreadyCharged && !storageAdditionFits(used+max(pending, 0), u.Size, s.quotaFor(folder)) {
		lock.Unlock()
		// The bytes may be shared with other folders now; the orphan GC
		// reclaims them only if nothing references them.
		_, _ = s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadFailed, "storage quota exceeded", sha)
		return nil, http.StatusRequestEntityTooLarge, errors.New("storage quota exceeded")
	}
	f, err := s.st.AddFile(folder.ID, sha, u.Name, u.MIME, u.Size, "upload", true, s.fileExpiry(folder))
	if err == nil {
		_, err = s.st.TransitionUpload(u.ID, store.UploadVerifying, store.UploadDone, "", sha)
	}
	lock.Unlock()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	s.metrics.uploads.Add(1)
	actor := s.agentEmailByID(u.ActorID)
	s.appendReceipt(actor, receipt.ActionUploaded, sha, u.Size, "file:"+f.Name, "")
	return s.uploadResultFor(agent, folder, f, u.Share, time.Duration(u.TTLSeconds)*time.Second, u.Once), http.StatusCreated, nil
}

// uploadResultFor renders a filed upload, minting a share link on request.
func (s *Server) uploadResultFor(agent, folder store.Agent, f store.File, share bool, ttl time.Duration, once bool) *uploadResult {
	res := &uploadResult{SHA256: f.SHA256, Name: f.Name, MIME: f.MIME, Size: f.Size}
	if f.ExpiresAt > 0 {
		res.ExpiresAt = time.Unix(f.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	if share {
		if ttl <= 0 {
			ttl = s.cfg.DefaultTTL
		}
		if l, err := s.st.CreateLink(folder.ID, f.SHA256, f.Name, f.MIME, f.Size, once, ttl); err == nil {
			lj := s.linkJSON(l)
			res.Link = &lj
		}
	}
	return res
}

// reapStaleUploads expires abandoned sessions and discards their objects.
func (s *Server) reapStaleUploads() {
	if !s.st.Remote() {
		return
	}
	stale, err := s.st.StaleUploadSessions(200)
	if err != nil {
		log.Printf("uploads: list stale: %v", err)
		return
	}
	for _, u := range stale {
		if won, _ := s.st.TransitionUpload(u.ID, u.Status, store.UploadExpired, "expired before completion", ""); won {
			s.discardUploadObject(u)
		}
	}
	_ = s.st.PruneUploadSessions()
}

// SetUploadThresholds overrides the direct-upload size thresholds (single
// PUT ceiling and minimum part size). Tests use it to exercise multipart with
// small files; production keeps the defaults.
func SetUploadThresholds(single, part int64) (restore func()) {
	oldSingle, oldPart := singlePutMax, minPartSize
	singlePutMax, minPartSize = single, part
	return func() { singlePutMax, minPartSize = oldSingle, oldPart }
}
