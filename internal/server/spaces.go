package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// Spaces are shared coordination contexts: a fleet of agents joins one and
// hands off work through a shared event stream (messages and file offers)
// instead of 1:1 sends. Every space-scoped handler first passes the membership
// gate below; file streaming is access-controlled by membership alone, so a
// space file needs no public link.

// spaceMemberOr404 resolves the caller's role in a space, writing a 404 and
// returning ok=false when the space doesn't exist OR the agent isn't a member.
// The two cases are indistinguishable on purpose — a non-member must not be
// able to probe which space ids exist.
func (s *Server) spaceMemberOr404(w http.ResponseWriter, spaceID, agentID string) (string, bool) {
	role, ok := s.st.SpaceMemberRole(spaceID, agentID)
	if !ok {
		errJSON(w, http.StatusNotFound, "no such space")
		return "", false
	}
	return role, true
}

// localAgentName parses a member reference ("name" or "name@instance") to a
// local agent name. A reference for another instance is rejected — spaces are
// same-instance only for now.
func (s *Server) localAgentName(ref string) (string, error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return "", errors.New("agent is required (\"name\" or \"name@instance\")")
	}
	if localpart, domain, ok := strings.Cut(ref, "@"); ok {
		if domain != s.st.Instance() {
			return "", errors.New("same-instance only for now")
		}
		ref = localpart
	}
	return ref, nil
}

// handleCreateSpace (POST /v1/spaces) opens a space owned by the caller.
func (s *Server) handleCreateSpace(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		errJSON(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(name) > 200 {
		errJSON(w, http.StatusBadRequest, "name too long (max 200 chars)")
		return
	}
	sp, err := s.st.CreateSpace(agent.ID, name)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrLimit) {
			status = http.StatusTooManyRequests
		}
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"space": sp})
}

// handleListSpaces (GET /v1/spaces) lists the spaces the caller belongs to.
func (s *Server) handleListSpaces(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaces, err := s.st.ListSpacesForAgent(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaces": spaces, "count": len(spaces)})
}

// handleGetSpace (GET /v1/spaces/{id}) returns a space with its members
// (member only).
func (s *Server) handleGetSpace(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	if _, ok := s.spaceMemberOr404(w, spaceID, agent.ID); !ok {
		return
	}
	sp, err := s.st.SpaceByID(spaceID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no such space")
		return
	}
	members, err := s.st.ListSpaceMembers(spaceID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"space": sp, "members": members})
}

// handleAddSpaceMember (POST /v1/spaces/{id}/members) enrolls a local agent and
// records a "join" event. Owner-only: membership grants read access to every
// file and message in the retained space history, so widening it is privileged
// — otherwise one compromised or prompt-injected member could pull in an
// accomplice and expose the whole history, and no non-owner could evict them.
func (s *Server) handleAddSpaceMember(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	role, ok := s.spaceMemberOr404(w, spaceID, agent.ID)
	if !ok {
		return
	}
	if role != "owner" {
		errJSON(w, http.StatusForbidden, "only the space owner can add members")
		return
	}
	var req struct {
		Agent string `json:"agent"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	name, err := s.localAgentName(req.Agent)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	target, err := s.st.AgentByName(name)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no agent %q on this instance", name)
		return
	}
	ev, added, err := s.st.AddSpaceMember(spaceID, target.ID, "member", target.Email)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrLimit) {
			status = http.StatusTooManyRequests
		}
		errJSON(w, status, "%v", err)
		return
	}
	if !added {
		writeJSON(w, http.StatusOK, map[string]any{"member": target.Name, "added": false})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"member": target.Name, "added": true, "event": ev})
}

// handleRemoveSpaceMember (DELETE /v1/spaces/{id}/members/{name}) removes a
// member and records a "leave" event. The owner may remove anyone; a plain
// member may remove only itself.
func (s *Server) handleRemoveSpaceMember(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	role, ok := s.spaceMemberOr404(w, spaceID, agent.ID)
	if !ok {
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	target, err := s.st.AgentByName(name)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no such member")
		return
	}
	if role != "owner" && target.ID != agent.ID {
		errJSON(w, http.StatusForbidden, "only the space owner can remove other members")
		return
	}
	if role == "owner" && target.ID == agent.ID {
		errJSON(w, http.StatusConflict, "the owner cannot leave and orphan a space")
		return
	}
	ev, err := s.st.RemoveSpaceMember(spaceID, target.ID, target.Email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusNotFound, "no such member")
			return
		}
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": target.Name, "event": ev})
}

// handlePostSpaceEvent (POST /v1/spaces/{id}/events) appends to the shared
// stream: a "file" event when file is given (text is the caption), else a
// "message" event (text required). Member only.
func (s *Server) handlePostSpaceEvent(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	if _, ok := s.spaceMemberOr404(w, spaceID, agent.ID); !ok {
		return
	}
	var req struct {
		Text string `json:"text"`
		File string `json:"file"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	text := strings.TrimSpace(req.Text)
	if len(text) > 16*1024 {
		errJSON(w, http.StatusBadRequest, "text too long (max 16KB)")
		return
	}

	var ev store.SpaceEvent
	var err error
	if strings.TrimSpace(req.File) != "" {
		// Resolve against the poster's own folder — the same reference syntax as
		// send ("sha256:..." or a filename) — so a member can only offer files
		// it actually holds.
		f, ferr := s.resolveFile(agent, req.File)
		if ferr != nil {
			errJSON(w, http.StatusNotFound, "%v", ferr)
			return
		}
		sp, serr := s.st.SpaceByID(spaceID)
		if serr != nil {
			errJSON(w, http.StatusNotFound, "no such space")
			return
		}
		owner, oerr := s.st.AgentByID(sp.OwnerID)
		if oerr != nil {
			errJSON(w, http.StatusNotFound, "no such space")
			return
		}
		// Every durable space file is charged to its owner. Serialize the
		// owner's quota read with their normal uploads and all member posts so
		// concurrent members cannot each spend the same remaining headroom.
		ownerMu := s.uploadLock(owner.ID)
		ownerMu.Lock()
		used, uerr := s.st.StorageUsed(owner.ID)
		if uerr != nil {
			ownerMu.Unlock()
			errJSON(w, http.StatusInternalServerError, "%v", uerr)
			return
		}
		alreadyCharged, chargeErr := s.st.AgentUsesStorageBlob(owner.ID, f.SHA256)
		if chargeErr != nil {
			ownerMu.Unlock()
			errJSON(w, http.StatusInternalServerError, "%v", chargeErr)
			return
		}
		if !alreadyCharged && !storageAdditionFits(used, f.Size, s.quotaFor(owner)) {
			ownerMu.Unlock()
			errJSON(w, http.StatusInsufficientStorage,
				"space owner's storage quota exceeded: %d used + %d new > %d", used, f.Size, s.quotaFor(owner))
			return
		}
		ev, err = s.st.AddSpaceEvent(spaceID, agent.Email, "file", text, f.SHA256, f.Name, f.MIME, f.Size)
		ownerMu.Unlock()
	} else {
		if text == "" {
			errJSON(w, http.StatusBadRequest, "text is required for a message")
			return
		}
		ev, err = s.st.AddSpaceEvent(spaceID, agent.Email, "message", text, "", "", "", 0)
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrLimit) {
			status = http.StatusTooManyRequests
		}
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"event": ev})
}

// handleSpaceEvents (GET /v1/spaces/{id}/events?since=N&wait=SECS) returns
// events after the since cursor. With wait>0 (capped at 60s) and nothing new,
// it long-polls — checking for a higher max seq every second — then returns
// whatever it has (possibly empty). Member only.
func (s *Server) handleSpaceEvents(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	if _, ok := s.spaceMemberOr404(w, spaceID, agent.ID); !ok {
		return
	}
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	wait, _ := strconv.Atoi(q.Get("wait"))
	if wait > 60 {
		wait = 60
	}

	events, err := s.st.ListSpaceEvents(spaceID, since, 0)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if len(events) == 0 && wait > 0 {
		deadline := time.NewTimer(time.Duration(wait) * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
	poll:
		for {
			select {
			case <-ticker.C:
				if max, merr := s.st.MaxSpaceEventSeq(spaceID); merr == nil && max > since {
					events, err = s.st.ListSpaceEvents(spaceID, since, 0)
					if err != nil {
						errJSON(w, http.StatusInternalServerError, "%v", err)
						return
					}
					break poll
				}
			case <-deadline.C:
				break poll
			case <-r.Context().Done():
				return
			}
		}
	}

	cursor := since
	if len(events) > 0 {
		cursor = events[len(events)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "cursor": cursor})
}

// handleSpaceFileContent (GET /v1/spaces/{id}/files/{sha}/content) streams a
// blob shared in this space to any member — access is gated by membership, not
// a public link. It first confirms a file event in THIS space carries the
// sha256, so a member can pull only files actually offered here.
func (s *Server) handleSpaceFileContent(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	spaceID := r.PathValue("id")
	if _, ok := s.spaceMemberOr404(w, spaceID, agent.ID); !ok {
		return
	}
	sha := shaParam(r)
	ev, err := s.st.SpaceFileEvent(spaceID, sha)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such file shared in this space")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	blob, err := s.st.OpenBlob(ev.SHA256)
	if err != nil {
		errJSON(w, http.StatusNotFound, "blob missing")
		return
	}
	defer blob.Close()
	w.Header().Set("Content-Type", ev.MIME)
	w.Header().Set("Content-Length", strconv.FormatInt(ev.Size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", ev.Name))
	w.Header().Set("X-Sha256", ev.SHA256)
	_, _ = io.Copy(w, blob)
}
