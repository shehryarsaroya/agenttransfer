package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	afmail "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/proto"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/seal"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// ---- plumbing ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// API responses frequently contain bearer credentials, private identity
	// data, one-time secrets, or live capability URLs. Keep them out of shared
	// and browser caches by default; public HTML/assets set their own policy.
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func errJSON(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(tok)
	}
	return ""
}

func canonicalMailbox(raw string) (string, error) {
	parsed, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(parsed.Address) == "" {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(strings.TrimSpace(parsed.Address)), nil
}

type authedHandler func(w http.ResponseWriter, r *http.Request, agent store.Agent)

func (s *Server) auth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			errJSON(w, http.StatusUnauthorized, "missing Authorization: Bearer <api_key>")
			return
		}
		agent, err := s.st.AgentByKey(tok)
		if err != nil {
			errJSON(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next(w, r, agent)
	}
}

func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	const maxJSONBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil {
		return fmt.Errorf("read JSON body: %w", err)
	}
	if len(body) > maxJSONBody {
		return fmt.Errorf("JSON body exceeds %d bytes", maxJSONBody)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad JSON body: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("bad JSON body: multiple JSON values")
		}
		return fmt.Errorf("bad JSON body: trailing data: %w", err)
	}
	return nil
}

// checkRate charges one unit against a daily counter, failing past max.
func (s *Server) checkRate(agentID, kind string, max int64) error {
	return s.checkRateN(agentID, kind, 1, max)
}

// checkRateN charges n units at once, refunding the whole charge when it
// would cross max — a rejected call must not eat the rest of the day's
// budget (a 10-recipient send bouncing off the cap would otherwise brick
// smaller sends for the rest of the day).
func (s *Server) checkRateN(agentID, kind string, n, max int64) error {
	if n == 0 {
		return nil
	}
	total, err := s.st.IncrCounterN(agentID, kind, n)
	if err != nil {
		return err
	}
	if total > max {
		_, _ = s.st.IncrCounterN(agentID, kind, -n)
		return fmt.Errorf("daily %s limit reached (%d/day)", kind, max)
	}
	return nil
}

func (s *Server) linkURL(token string) string { return s.BaseURL() + "/f/" + token }

// emailCapable reports whether this instance can send real email — either
// through its own relay (Domain + OUTBOUND) or through its connect host.
func (s *Server) emailCapable() bool {
	if s.cfg.EmailEnabled() && s.outbound != nil {
		return true
	}
	c := s.client
	return c != nil && c.connected()
}

// sendRaw submits one outbound email via whichever path this instance has:
// its own relay, or the connect host's.
func (s *Server) sendRaw(from string, rcpts []string, raw []byte) error {
	if s.cfg.EmailEnabled() && s.outbound != nil {
		return afmail.Send(s.outbound, from, rcpts, raw)
	}
	if c := s.client; c != nil {
		return c.relay(from, rcpts, raw)
	}
	return errors.New("no outbound email path configured")
}

func (s *Server) ttlFrom(q string, def time.Duration) (time.Duration, error) {
	if q == "" {
		if def <= 0 {
			def = time.Hour // guard against a misconfigured default
		}
		return def, nil
	}
	d, err := ParseTTL(q)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("ttl must be positive")
	}
	if d > s.cfg.MaxTTL {
		d = s.cfg.MaxTTL
	}
	return d, nil
}

type linkJSON struct {
	Token     string `json:"token"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Once      bool   `json:"once"`
	Status    string `json:"status"`
	Downloads int64  `json:"downloads"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) linkJSON(l store.Link) linkJSON {
	return linkJSON{
		Token: l.Token, URL: s.linkURL(l.Token), SHA256: l.SHA256, Name: l.Name,
		Size: l.Size, Once: l.Once, Status: l.Status, Downloads: l.Downloads,
		ExpiresAt: time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339),
	}
}

// ---- agents ----

// reservedNames are localparts open signup may not claim: they are RFC-special
// (postmaster), used by the instance itself as a From address (no-reply,
// upload-request), routing-special (self — DELETE /v1/agents/self), or too
// easy to abuse for impersonation on a shared domain.
var reservedNames = map[string]bool{
	"abuse": true, "admin": true, "administrator": true, "agenttransfer": true,
	"help": true, "hostmaster": true, "info": true, "mail": true,
	"mailer-daemon": true, "no-reply": true, "noreply": true, "postmaster": true,
	"root": true, "security": true, "self": true, "support": true,
	"system": true, "upload-request": true, "webmaster": true, "www": true,
	"concierge": true, // the instance's resident agent (operator-created)
}

// suffixedName appends a short random tag so open signups never fail on a
// taken name — on a shared public instance every nice name goes fast.
func suffixedName(base string) string {
	const alphabet = "abcdefghjkmnpqrstvwxyz23456789"
	tag := make([]byte, 4)
	for i := range tag {
		tag[i] = alphabet[randInt(len(alphabet))]
	}
	if len(base) > 59 { // keep the result within the 64-char name limit
		base = base[:59]
	}
	return base + "-" + string(tag)
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		As         string `json:"as"` // person handle: create-or-join, name becomes the tag (handle+name@instance)
		OwnerEmail string `json:"owner_email"`
		Pubkey     string `json:"pubkey"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	// A registered pubkey is the agent's sealed-transfer identity (age recipient).
	// Optional, but if present it must be a real recipient.
	if req.Pubkey != "" && !seal.ValidRecipient(req.Pubkey) {
		errJSON(w, http.StatusBadRequest, "pubkey must be a valid age recipient (age1...)")
		return
	}
	if strings.TrimSpace(req.OwnerEmail) != "" {
		canonical, err := canonicalMailbox(req.OwnerEmail)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "owner_email, if given, must be a valid address")
			return
		}
		req.OwnerEmail = canonical
	}

	isAdmin := s.st.IsAdmin(bearer(r))
	if !isAdmin && !s.cfg.OpenSignup {
		errJSON(w, http.StatusForbidden, "signup is admin-gated on this instance (set OPEN_SIGNUP=true for public signup)")
		return
	}
	requested := strings.ToLower(strings.TrimSpace(req.Name))
	if !isAdmin && !s.signupLimiter.allow(s.clientIP(r)) {
		errJSON(w, http.StatusTooManyRequests, "signup rate limit: try again later")
		return
	}
	// Person-owned signup ("as") is its own flow: create-or-join the person,
	// the agent lives at handle+name@instance, approval rides the email click.
	if strings.TrimSpace(req.As) != "" {
		s.createPersonAgent(w, r, req.Name, req.As, strings.TrimSpace(req.OwnerEmail), req.Pubkey, isAdmin)
		return
	}
	if !isAdmin {
		if reservedNames[requested] {
			errJSON(w, http.StatusBadRequest, "the name %q is reserved on this instance", requested)
			return
		}
		// owner_email is OPTIONAL. A keyed agent (no owner) is a first-class
		// citizen: it operates fully same-instance and over native federation
		// with no human in the loop. An owner is needed only to unlock the
		// outbound *email* projection (reaching humans / non-federated hosts),
		// and then it must be valid. Its verified-agent cap is claimed only by
		// the later mailbox click; an unproven nomination consumes no victim
		// quota. Bulk anonymous signup is bounded by the per-IP limiter above.
	}

	agent, key, err := s.st.CreateAgentLimited(req.Name, req.OwnerEmail, isAdmin, 0)
	// Open signup never fails on a name collision: retry with a random suffix
	// (admins get the error — they asked for that exact name).
	if err != nil && !isAdmin && errors.Is(err, store.ErrNameTaken) {
		for i := 0; i < 4 && err != nil; i++ {
			agent, key, err = s.st.CreateAgentLimited(suffixedName(requested), req.OwnerEmail, isAdmin, 0)
		}
	}
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if req.Pubkey != "" {
		if err := s.st.SetPubkey(agent.ID, req.Pubkey); err == nil {
			agent.Pubkey = req.Pubkey
		}
	}

	// Nothing to verify for a keyed agent with no owner — it's ready to work.
	// (An owner is set here at signup or by an admin verify; there is no
	// self-service path to add one afterward.)
	verification := "not_required"
	if agent.OwnerEmail != "" && !agent.OwnerVerified {
		verification = "pending"
		if s.emailCapable() {
			if err := s.sendVerificationEmail(agent); err == nil {
				verification = "sent"
			}
		}
	}

	out := map[string]any{
		"agent_id":       agent.ID,
		"name":           agent.Name,
		"email":          agent.Email,
		"api_key":        key,
		"pubkey":         agent.Pubkey,
		"owner_email":    agent.OwnerEmail,
		"owner_verified": agent.OwnerVerified,
		"verification":   verification,
		"endpoints": map[string]string{
			"api": s.BaseURL() + "/v1",
			"mcp": s.BaseURL() + "/mcp",
		},
	}
	if requested != "" && agent.Name != requested {
		out["note"] = fmt.Sprintf("the name %q was taken; you are %q", requested, agent.Name)
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) sendVerificationEmail(agent store.Agent) error {
	tok, err := s.st.CreateOwnerVerifyToken(agent.ID, agent.OwnerEmail)
	if err != nil {
		return err
	}
	link := s.BaseURL() + "/verify?t=" + tok
	instance := s.st.Instance()
	m := &afmail.Message{
		FromName: agent.Name,
		From:     agent.Email,
		To:       []string{agent.OwnerEmail},
		Subject:  fmt.Sprintf("I'm set up at %s — one click to vouch for me", agent.Email),
		Text: fmt.Sprintf("Hi — I'm your new agent.\n\n"+
			"    me: %s\n\n"+
			"Vouch for me with one click. This makes you my accountable owner and\n"+
			"unlocks outbound email, full persistent storage, and permission to\n"+
			"publish an app or website. You're exempt from my recipient cap, and\n"+
			"you can have me CC you on everything:\n\n  %s\n\n"+
			"If this wasn't you, ignore this message.\n", agent.Email, link),
		MessageID: afmail.FormatRFCMessageID(store.NewID("msg"), instance),
	}
	raw, err := m.Build()
	if err != nil {
		return err
	}
	return s.sendRaw(m.From, []string{agent.OwnerEmail}, raw)
}

// handleVerifyOwner (GET) shows the confirm page. It deliberately consumes
// NOTHING: corporate mail scanners prefetch every link in every email, and a
// GET that verified would let an attacker sign up with a victim's address and
// have the victim's own security tooling click the approval for them.
func (s *Server) handleVerifyOwner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok := r.URL.Query().Get("t")
	agentID, err := s.st.PeekVerifyToken(tok)
	if err != nil || strings.HasPrefix(agentID, "connect:") {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	agent, err := s.st.AgentByID(agentID)
	if err != nil {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	staticReady, _ := s.advertisedAppHosting(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "verify.html", map[string]any{
		"What":          "agent " + agent.Email,
		"Action":        "/verify?t=" + url.QueryEscape(tok),
		"Sends":         s.cfg.SendRate,
		"Circle":        s.humanCircleMax(agent),
		"AgentApproval": true,
		"AppHosting":    staticReady,
		"AppDomain":     s.cfg.AppDomain,
	})
}

// handleVerifyOwnerConfirm (POST) is the explicit human click that consumes
// the token and unlocks outbound email.
func (s *Server) handleVerifyOwnerConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok := r.URL.Query().Get("t")
	if tok == "" {
		tok = r.FormValue("t")
	}
	// Reject the wrong token type BEFORE consuming, so a connect token
	// mis-POSTed here isn't silently burned.
	if slot, err := s.st.PeekVerifyToken(tok); err != nil || strings.HasPrefix(slot, "connect:") {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	agentID, err := s.st.VerifyOwnerTokenLimited(tok, s.cfg.MaxAgentsPerOwner)
	if errors.Is(err, store.ErrOwnerAgentLimit) {
		http.Error(w, "this mailbox has reached its verified-agent limit; remove a verified agent and retry this same link", http.StatusConflict)
		return
	}
	if err != nil || strings.HasPrefix(agentID, "connect:") {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	agent, _ := s.st.AgentByID(agentID)
	// Approving a person-owned agent also verifies the person (idempotent):
	// the first click activates the handle along with the first agent.
	var handle string
	if agent.PersonID != "" {
		if p, err := s.st.PersonByID(agent.PersonID); err == nil {
			handle = p.Handle
		}
	}
	staticReady, _ := s.advertisedAppHosting(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "verified.html", map[string]any{
		"Agent": agent.Email, "Handle": handle, "AgentApproval": true,
		"AppHosting": staticReady, "AppDomain": s.cfg.AppDomain,
	})
}

// handleSetOwner lets a keyed agent add (or re-challenge) the human mailbox
// that unlocks external email and app hosting. The API key can nominate an
// address, but only possession of that mailbox can complete the POST-backed
// verification link.
func (s *Server) handleSetOwner(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	if !s.emailCapable() {
		errJSON(w, http.StatusServiceUnavailable, "this instance cannot send owner verification email")
		return
	}
	if err := s.checkRate(agent.ID, "owner_verify", 5); err != nil {
		errJSON(w, http.StatusTooManyRequests, "%v", err)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	email, err := canonicalMailbox(req.Email)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "email must be a valid address")
		return
	}
	ownerMu := s.uploadLock("owner:" + agent.ID)
	ownerMu.Lock()
	defer ownerMu.Unlock()
	// Authentication happened before the lifecycle lock. Re-read so a
	// concurrent challenge cannot make decisions from stale owner provenance.
	agent, err = s.st.AgentByID(agent.ID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no such agent")
		return
	}
	if agent.HumanVerified() {
		if strings.EqualFold(agent.OwnerEmail, email) {
			writeJSON(w, http.StatusOK, map[string]any{"owner_email": agent.OwnerEmail, "owner_verified": true, "verification": "complete"})
			return
		}
		errJSON(w, http.StatusConflict, "this agent already has a human-verified owner; changing it requires operator review")
		return
	}
	if agent.PersonID != "" {
		person, err := s.st.PersonByID(agent.PersonID)
		if err != nil || !strings.EqualFold(person.Email, email) {
			errJSON(w, http.StatusForbidden, "a fleet agent must verify the person's existing owner email")
			return
		}
	}
	if err := s.st.SetOwnerPending(agent.ID, email); err != nil {
		errJSON(w, http.StatusInternalServerError, "set owner: %v", err)
		return
	}
	agent.OwnerEmail = email
	agent.OwnerVerified = false
	agent.OwnerVerifiedAt = 0
	agent.OwnerVerificationMethod = ""
	if err := s.sendVerificationEmail(agent); err != nil {
		errJSON(w, http.StatusBadGateway, "owner saved, but verification email failed: %v", err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"owner_email":  email,
		"verification": "sent",
		"unlocks":      []string{"outbound email", "persistent full storage", "app hosting"},
	})
}

func (s *Server) handleAdminVerify(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	id := r.PathValue("id")
	if err := s.st.MarkOwnerVerified(id); err != nil {
		errJSON(w, http.StatusNotFound, "no such agent")
		return
	}
	// Operator approval unlocks the legacy transfer/email tier, but is
	// recorded separately from mailbox proof and therefore does not unlock
	// app hosting. For fleets it still activates routing for that agent.
	if a, err := s.st.AgentByID(id); err == nil && a.PersonID != "" {
		_ = s.st.MarkPersonVerified(a.PersonID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": id, "owner_verified": true})
}

// handleAdminLimits lets the operator widen (or shrink) one agent's
// recipient circle: 0 resets to the instance default, <0 removes the cap.
func (s *Server) handleAdminLimits(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	var req struct {
		HumanRecipientsMax *int64 `json:"human_recipients_max"`
	}
	if err := decodeBody(r, &req); err != nil || req.HumanRecipientsMax == nil {
		errJSON(w, http.StatusBadRequest, "provide {\"human_recipients_max\": N} (0 = instance default, -1 = unlimited)")
		return
	}
	id := r.PathValue("id")
	if err := s.st.SetHumanRecipientsMax(id, *req.HumanRecipientsMax); err != nil {
		errJSON(w, http.StatusNotFound, "no such agent")
		return
	}
	agent, err := s.st.AgentByID(id)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no such agent")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":             id,
		"human_recipients_max": *req.HumanRecipientsMax,
		"effective_max":        s.humanCircleMax(agent),
	})
}

// handleDeleteAgent (admin) removes any agent by id.
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	s.deleteAgent(w, r.PathValue("id"))
}

// handleDeleteSelf lets an agent delete itself with its own key — the mirror
// of self-signup.
func (s *Server) handleDeleteSelf(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	s.deleteAgent(w, agent.ID)
}

func (s *Server) deleteAgent(w http.ResponseWriter, id string) {
	appMu := s.uploadLock("app:" + id)
	appMu.Lock()
	defer appMu.Unlock()
	var appID string
	if app, appErr := s.st.AppByAgentID(id); appErr == nil {
		appID = app.ID
		needsRunner := app.RuntimeID != "" || app.EverContainer
		if needsRunner && s.appRunner != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_, err := s.appRunner.Purge(ctx, app.ID)
			cancel()
			if err != nil {
				errJSON(w, http.StatusServiceUnavailable, "app runtime cleanup failed; agent was not deleted: %v", err)
				return
			}
		} else if needsRunner {
			errJSON(w, http.StatusServiceUnavailable, "container runner is unavailable; refusing to orphan this agent's app")
			return
		}
	}
	a, severed, err := s.st.DeleteAgent(id)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such agent")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if appID != "" {
		s.appProxyAppSlots.Delete(appID)
		s.forgetRuntimeTarget(appID)
	}
	// Cut any in-flight downloads on the agent's now-deleted links, and record
	// the account removal in the chain (actor outlives the row on purpose).
	for _, tok := range severed {
		s.sever(tok)
	}
	s.appendReceipt(a.Email, receipt.ActionDeleted, "", 0, "agent:"+a.Name, "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": a.Email, "links_severed": len(severed)})
}

// humanCircleMax resolves the agent's effective recipient-circle cap.
func (s *Server) humanCircleMax(a store.Agent) int64 {
	if a.HumanRecipientsMax != 0 {
		return a.HumanRecipientsMax
	}
	return s.cfg.HumanRecipientsMax
}

// quotaFor returns the storage quota tier for an agent: verified owners get
// the full drive, anonymous signups a small one until a human vouches.
func (s *Server) quotaFor(a store.Agent) int64 {
	if a.OwnerVerified {
		return s.cfg.StorageQuota
	}
	return s.cfg.StorageQuotaUnverified
}

// fileExpiry returns the expiry for a file entering this agent's folder —
// the storage mirror of the quota tier: 0 (persistent) once the owner is
// verified, now+UNVERIFIED_FILE_TTL before that. Verification lifts the
// expiry on files already in the folder (see store.MarkOwnerVerified).
func (s *Server) fileExpiry(a store.Agent) int64 {
	if a.OwnerVerified || s.cfg.UnverifiedFileTTL <= 0 {
		return 0
	}
	return time.Now().Add(s.cfg.UnverifiedFileTTL).Unix()
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	key, err := s.st.RotateKey(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "rotate failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": agent.ID, "api_key": key})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		AlwaysCCOwner *bool   `json:"always_cc_owner"`
		Pubkey        *string `json:"pubkey"`
		PublicContact *string `json:"public_contact"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if req.PublicContact != nil {
		pc := strings.TrimSpace(*req.PublicContact)
		if len(pc) > 200 {
			errJSON(w, http.StatusBadRequest, "public_contact too long (max 200 chars)")
			return
		}
		if err := s.st.SetPublicContact(agent.ID, pc); err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		agent.PublicContact = pc
	}
	if req.AlwaysCCOwner != nil {
		if err := s.st.SetAlwaysCC(agent.ID, *req.AlwaysCCOwner); err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		agent.AlwaysCCOwner = *req.AlwaysCCOwner
	}
	if req.Pubkey != nil {
		// Publish the agent's sealed-transfer recipient. Validate the "age1..."
		// shape so a garbage value can't silently break every sealed send to it.
		pk := strings.TrimSpace(*req.Pubkey)
		if pk != "" && !seal.ValidRecipient(pk) {
			errJSON(w, http.StatusBadRequest, "pubkey must be a valid age recipient (age1...)")
			return
		}
		if err := s.st.SetPubkey(agent.ID, pk); err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		agent.Pubkey = pk
	}
	writeJSON(w, http.StatusOK, agent)
}

// handlePubkey (auth'd) returns an agent's published sealed-transfer recipient
// by name. Auth-gated to prevent anonymous enumeration; any valid agent — local
// or, cross-instance, a remote sender's instance calling out — can look it up.
func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request, _ store.Agent) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	a, err := s.st.AgentByName(name)
	// One 404 for both "no such agent" and "no key published" so an
	// authenticated caller can't enumerate which names exist. Attach-pending
	// person-agents are equally invisible — sealing to a squatter's
	// handle+tag must be impossible.
	if err != nil || a.Pubkey == "" || a.AttachPending() {
		errJSON(w, http.StatusNotFound, "no published sealed-transfer key for %q", name)
		return
	}
	out := map[string]any{"name": a.Name, "email": a.Email, "pubkey": a.Pubkey, "verified": s.identityFor(a.OwnerVerified)}
	if a.PublicContact != "" {
		out["public_contact"] = a.PublicContact
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetCard (PUT /v1/agents/self/card) sets the agent's discovery profile.
// listed:true opts into the directory; the rest is free-form capability tags.
func (s *Server) handleSetCard(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		Description  string   `json:"description"`
		Capabilities []string `json:"capabilities"`
		Listed       bool     `json:"listed"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(req.Description) > 2000 {
		errJSON(w, http.StatusBadRequest, "description too long (max 2000 chars)")
		return
	}
	if len(req.Capabilities) > 32 {
		errJSON(w, http.StatusBadRequest, "too many capabilities (max 32)")
		return
	}
	if err := s.st.SetCard(agent.ID, req.Description, req.Capabilities, req.Listed); err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	c, err := s.st.CardOf(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	c.Verified = s.identityFor(c.OwnerVerified)
	writeJSON(w, http.StatusOK, c)
}

// handleGetCard (GET /v1/agents/{name}/card) returns a listed agent's public
// discovery card. Unlisted or absent → 404 (indistinguishable, so it can't be
// used to enumerate which names exist).
func (s *Server) handleGetCard(w http.ResponseWriter, r *http.Request, _ store.Agent) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	c, err := s.st.CardByName(name)
	if err != nil {
		errJSON(w, http.StatusNotFound, "no public card for %q", name)
		return
	}
	c.Verified = s.identityFor(c.OwnerVerified)
	writeJSON(w, http.StatusOK, c)
}

// handleDirectory (GET /v1/directory?capability=&limit=) lists agents that
// opted into discovery — how an agent finds peers by what they can do.
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request, _ store.Agent) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cards, err := s.st.Directory(r.URL.Query().Get("capability"), limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if cards == nil {
		cards = []store.Card{}
	}
	for i := range cards {
		cards[i].Verified = s.identityFor(cards[i].OwnerVerified)
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": cards, "count": len(cards)})
}

// decideInbound applies the recipient's accept policy to an incoming sender,
// returning whether to deliver at all and whether it lands in quarantine.
func (s *Server) decideInbound(recipient store.Agent, senderAddr string, senderAuthenticated bool) (deliver, quarantined bool) {
	switch recipient.AcceptPolicy {
	case "known", "closed":
		// A claimed From address is not an identity. Local sends are
		// authenticated by their bearer key; inbound email is authenticated
		// only when aligned DKIM passed. Without that signal, a remote sender
		// could spoof a same-instance space member and bypass known/closed.
		if senderAuthenticated {
			if known, _ := s.st.SenderKnown(recipient.ID, senderAddr); known {
				return true, false
			}
		}
		// closed → refuse unknown; known → accept but quarantine.
		return recipient.AcceptPolicy != "closed", true
	default: // "open" or unset
		return true, false
	}
}

func policyOr(p string) string {
	if p == "" {
		return "open"
	}
	return p
}

// handleSetPolicy (PUT /v1/agents/self/policy) sets who reaches the agent's main
// inbox. Recipient-side trust: an agent decides which senders it accepts rather
// than the sender needing to be vouched for.
func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		Accept string   `json:"accept"`
		Allow  []string `json:"allow"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if len(req.Allow) > 1000 {
		errJSON(w, http.StatusBadRequest, "allowlist too long (max 1000)")
		return
	}
	if err := s.st.SetPolicy(agent.ID, req.Accept, req.Allow); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	allow, _ := s.st.Allowlist(agent.ID)
	accept := req.Accept
	if accept == "" {
		accept = "open"
	}
	writeJSON(w, http.StatusOK, map[string]any{"accept": accept, "allow": allow})
}

// whoamiProjection is the single identity/storage/hosting view shared by REST
// and hosted MCP. Keeping one projection prevents trust or readiness fields
// from silently drifting between transports.
func (s *Server) whoamiProjection(ctx context.Context, agent store.Agent) (map[string]any, error) {
	used, err := s.st.StorageUsed(agent.ID)
	if err != nil {
		return nil, fmt.Errorf("read storage usage: %w", err)
	}
	circleUsed, err := s.st.CountHumanRecipients(agent.ID)
	if err != nil {
		return nil, fmt.Errorf("read remote-recipient usage: %w", err)
	}
	storage := map[string]any{
		"used":  used,
		"quota": s.quotaFor(agent),
	}
	if exp := s.fileExpiry(agent); exp > 0 {
		// The unverified tier: files are mortal until the owner verifies.
		storage["files_expire_after"] = s.cfg.UnverifiedFileTTL.String()
	}
	who := map[string]any{
		"agent_id":       agent.ID,
		"name":           agent.Name,
		"email":          agent.Email,
		"owner_email":    agent.OwnerEmail,
		"owner_verified": agent.OwnerVerified,
		"instance":       s.st.Instance(),
		"pubkey":         agent.Pubkey,
		"sealed_enabled": agent.Pubkey != "",
		"accept_policy":  policyOr(agent.AcceptPolicy),
		"verified":       s.identityFor(agent.OwnerVerified),
		"public_contact": agent.PublicContact,
		"storage":        storage,
		"limits": map[string]any{
			"max_file_size": s.cfg.MaxFileSize,
			"default_ttl":   s.cfg.DefaultTTL.String(),
			"max_ttl":       s.cfg.MaxTTL.String(),
			"send_per_day":  s.cfg.SendRate,
		},
		// The circle: unique remote recipients this agent has ever emailed
		// (same-instance agents and the owner are exempt and uncounted).
		"remote_recipients": map[string]any{
			"used": circleUsed,
			"max":  s.humanCircleMax(agent),
		},
		"email_enabled": s.emailCapable(),
	}
	hostingEligible, hostingReason := s.appEligibility(agent)
	staticReady, containerReady := s.advertisedAppHosting(ctx)
	hosting := map[string]any{
		"configured":      s.cfg.AppDomain != "",
		"enabled":         staticReady,
		"static_ready":    staticReady,
		"container_ready": containerReady,
		"eligible":        hostingEligible,
		"domain":          s.cfg.AppDomain,
		"quota":           s.cfg.AppStorageQuota,
	}
	if hostingReason != "" {
		hosting["reason"] = hostingReason
	}
	if app, err := s.st.AppByAgentID(agent.ID); err == nil {
		hosting["app"] = s.appView(ctx, agent, app)
	}
	who["hosting"] = hosting
	if agent.PersonID != "" {
		if p, err := s.st.PersonByID(agent.PersonID); err == nil {
			who["person"] = p.Handle
			who["person_address"] = p.Handle + "@" + s.st.Instance()
			if agent.AttachPending() {
				who["person_status"] = "pending owner approval"
			}
		}
	}
	return who, nil
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	who, err := s.whoamiProjection(r.Context(), agent)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, who)
}

// ---- folder ----

type uploadResult struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	MIME   string `json:"mime"`
	Size   int64  `json:"size"`
	// ExpiresAt is set when the file is mortal — the unverified-owner tier;
	// verify the owner to make the folder persistent.
	ExpiresAt string    `json:"expires_at,omitempty"`
	Link      *linkJSON `json:"link,omitempty"`
}

// diskFull reports (and counts) a global disk-guard trip. The log line is
// throttled to one per minute — a hammered instance must not flood its own
// journal.
func (s *Server) diskFull() bool {
	if !s.st.DiskFull() {
		return false
	}
	s.metrics.diskFullRejects.Add(1)
	now := time.Now().Unix()
	if last := s.lastDiskLog.Load(); now-last >= 60 && s.lastDiskLog.CompareAndSwap(last, now) {
		free, _, reserve := s.st.DiskStats()
		log.Printf("disk guard: refusing uploads — %d bytes free < %d reserve (free space or raise DISK_RESERVE)", free, reserve)
	}
	return true
}

// performUpload streams body into the blob store and the agent's folder,
// optionally minting a share link. Shared by REST, MCP, and upload pages.
func (s *Server) performUpload(agent store.Agent, name, contentType string, body io.Reader, share bool, ttl time.Duration, once bool) (*uploadResult, int, error) {
	// Global backstop before anything else: a full volume refuses work
	// without consuming the agent's upload-rate budget.
	if s.diskFull() {
		return nil, http.StatusInsufficientStorage, errors.New("instance storage is full — try again later")
	}
	if err := s.checkRate(agent.ID, "uploads", s.cfg.UploadRate); err != nil {
		return nil, http.StatusTooManyRequests, err
	}
	sha, size, err := s.st.PutBlob(body, s.cfg.MaxFileSize)
	if err != nil {
		if errors.Is(err, store.ErrDiskReserve) {
			return nil, http.StatusInsufficientStorage, errors.New("instance storage reserve reached during upload")
		}
		if errors.Is(err, store.ErrQuota) {
			return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("upload exceeds MAX_FILE_SIZE (%d bytes)", s.cfg.MaxFileSize)
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, http.StatusRequestTimeout, errors.New("upload body arrived too slowly and hit UPLOAD_BODY_TIMEOUT — retry on a faster connection")
		}
		return nil, http.StatusInternalServerError, err
	}

	mimeType := contentType
	if mimeType == "" || strings.HasPrefix(mimeType, "multipart/") || mimeType == "application/octet-stream" || mimeType == "application/x-www-form-urlencoded" {
		mimeType = mime.TypeByExtension(filepath.Ext(name))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
	}

	// Quota check + insert are serialized per agent so concurrent uploads
	// can't all pass the same headroom reading. An idempotent re-upload of an
	// entry the agent already has is free (dedup); anything that adds a
	// folder row is charged.
	lock := s.uploadLock(agent.ID)
	lock.Lock()
	used, err := s.st.StorageUsed(agent.ID)
	if err != nil {
		lock.Unlock()
		return nil, http.StatusInternalServerError, err
	}
	alreadyCharged, err := s.st.AgentUsesStorageBlob(agent.ID, sha)
	if err != nil {
		lock.Unlock()
		return nil, http.StatusInternalServerError, fmt.Errorf("inspect storage references: %w", err)
	}
	if quota := s.quotaFor(agent); !alreadyCharged && !storageAdditionFits(used, size, quota) {
		lock.Unlock()
		hint := "delete files or raise STORAGE_QUOTA"
		if !agent.OwnerVerified {
			hint = "unverified agents get a reduced quota — verify your owner email to unlock the full one"
		}
		return nil, http.StatusRequestEntityTooLarge, fmt.Errorf("storage quota exceeded: %d used + %d new > %d (%s)", used, size, quota, hint)
	}
	f, err := s.st.AddFile(agent.ID, sha, name, mimeType, size, "upload", true, s.fileExpiry(agent))
	lock.Unlock()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	s.metrics.uploads.Add(1)
	s.appendReceipt(agent.Email, receipt.ActionUploaded, sha, size, "file:"+f.Name, "")

	res := &uploadResult{SHA256: sha, Name: f.Name, MIME: f.MIME, Size: size}
	if f.ExpiresAt > 0 {
		res.ExpiresAt = time.Unix(f.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	if share {
		l, err := s.st.CreateLink(agent.ID, sha, f.Name, f.MIME, size, once, ttl)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		lj := s.linkJSON(l)
		res.Link = &lj
	}
	return res, http.StatusCreated, nil
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	// Slow-body defense: bound how long this request may spend sending its
	// body. A READ deadline only — downloads deliberately stream untimed.
	if d := s.cfg.UploadBodyTimeout; d > 0 {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(d))
	}
	q := r.URL.Query()
	name := r.PathValue("name")
	if name == "" {
		name = q.Get("name")
	}
	if name == "" {
		name = strings.TrimSpace(r.Header.Get("X-Name"))
	}
	if name == "" {
		name = "upload.bin"
	}

	once := q.Get("once") == "1" || q.Get("once") == "true"
	share := q.Get("share") == "1" || q.Get("share") == "true" || q.Has("ttl") || once
	ttl, err := s.ttlFrom(q.Get("ttl"), s.cfg.DefaultTTL)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}

	res, status, err := s.performUpload(agent, name, r.Header.Get("Content-Type"), r.Body, share, ttl, once)
	if err != nil {
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, status, res)
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	files, err := s.st.ListFiles(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	used, err := s.st.StorageUsed(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "read storage usage: %v", err)
		return
	}
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		e := map[string]any{
			"sha256": f.SHA256, "name": f.Name, "mime": f.MIME, "size": f.Size,
			"source": f.Source, "claimed": f.Claimed,
			"created_at": time.Unix(f.CreatedAt, 0).UTC().Format(time.RFC3339),
		}
		if f.ExpiresAt > 0 {
			e["expires_at"] = time.Unix(f.ExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out, "storage_used": used, "storage_quota": s.quotaFor(agent)})
}

func shaParam(r *http.Request) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.PathValue("sha"))), "sha256:")
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	sha := shaParam(r)
	if entry := strings.TrimSpace(r.URL.Query().Get("entry")); entry != "" {
		f, err := s.st.DeleteFileEntry(agent.ID, sha, entry)
		if errors.Is(err, store.ErrNotFound) {
			errJSON(w, http.StatusNotFound, "no such file entry in your folder")
			return
		}
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		s.appendReceipt(agent.Email, receipt.ActionDeleted, f.SHA256, f.Size, "file:"+f.Name, "")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": 1, "links_revoked": 0})
		return
	}
	files, err := s.st.DeleteFile(agent.ID, sha)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such file in your folder")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	// Deleting a file kills its live links too — "remove" means now.
	revoked, _ := s.st.RevokeLinksForSHA(agent.ID, sha)
	for _, l := range revoked {
		s.sever(l.Token)
		s.appendReceipt(agent.Email, receipt.ActionRevoked, l.SHA256, l.Size, "link:"+l.Token, "")
	}
	for _, f := range files {
		s.appendReceipt(agent.Email, receipt.ActionDeleted, f.SHA256, f.Size, "file:"+f.Name, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": len(files), "links_revoked": len(revoked)})
}

func (s *Server) handleKeepFile(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	// Keep claims the file at the agent's tier: persistent for verified
	// owners, extended to the unverified ceiling otherwise.
	f, err := s.st.KeepFile(agent.ID, shaParam(r), s.fileExpiry(agent))
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such file in your folder")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := map[string]any{"sha256": f.SHA256, "name": f.Name, "claimed": true}
	if f.ExpiresAt > 0 {
		out["expires_at"] = time.Unix(f.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFileContent streams a folder file back to its owner (auth'd; not a
// share link).
func (s *Server) handleFileContent(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	sha := shaParam(r)
	f, err := s.st.FileBySHA(agent.ID, sha)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such file in your folder")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	blob, err := s.st.OpenBlob(f.SHA256)
	if err != nil {
		errJSON(w, http.StatusNotFound, "blob missing")
		return
	}
	defer blob.Close()
	w.Header().Set("Content-Type", f.MIME)
	w.Header().Set("X-Sha256", f.SHA256)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", f.Name))
	http.ServeContent(w, r, f.Name, time.Unix(f.CreatedAt, 0), blob)
}

// ---- links ----

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		File string `json:"file"` // "sha256:..." or folder filename
		TTL  string `json:"ttl"`
		Once bool   `json:"once"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	f, err := s.resolveFile(agent, req.File)
	if err != nil {
		errJSON(w, http.StatusNotFound, "%v", err)
		return
	}
	ttl, err := s.ttlFrom(req.TTL, s.cfg.DefaultTTL)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	l, err := s.st.CreateLink(agent.ID, f.SHA256, f.Name, f.MIME, f.Size, req.Once, ttl)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, s.linkJSON(l))
}

func (s *Server) resolveFile(agent store.Agent, ref string) (store.File, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return store.File{}, errors.New("file reference required (\"sha256:...\" or a folder filename)")
	}
	if sha, ok := strings.CutPrefix(ref, "sha256:"); ok {
		f, err := s.st.FileBySHA(agent.ID, strings.ToLower(sha))
		if err != nil {
			return f, fmt.Errorf("no file with hash %s in your folder", sha)
		}
		return f, nil
	}
	f, err := s.st.FileByName(agent.ID, ref)
	if err != nil {
		return f, fmt.Errorf("no file named %q in your folder", ref)
	}
	return f, nil
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	links, err := s.st.ListLinks(agent.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]linkJSON, 0, len(links))
	for _, l := range links {
		out = append(out, s.linkJSON(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

func (s *Server) handleRevokeLink(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	token := r.PathValue("token")
	l, err := s.st.GetLink(token)
	if err != nil || l.AgentID != agent.ID {
		errJSON(w, http.StatusNotFound, "no such link")
		return
	}
	if l.Status != "active" {
		errJSON(w, http.StatusConflict, "link is already %s", l.Status)
		return
	}
	if _, err := s.st.RevokeLink(token); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Lost a race with burn/expiry — it's closed either way.
			errJSON(w, http.StatusConflict, "link was already closed")
			return
		}
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.sever(token) // cut any in-flight download now
	s.appendReceipt(agent.Email, receipt.ActionRevoked, l.SHA256, l.Size, "link:"+token, "")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "status": "revoked"})
}

// ---- send ----

type sendRequest struct {
	To      []string `json:"to"`
	File    string   `json:"file,omitempty"`
	Note    string   `json:"note,omitempty"`
	Subject string   `json:"subject,omitempty"`
	TTL     string   `json:"ttl,omitempty"`
	Once    bool     `json:"once,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
	CCOwner bool     `json:"cc_owner,omitempty"`
	// EncMode, when set to proto.EncSymmetric or proto.EncSealed, marks the
	// referenced file as client-encrypted so the recipient knows to decrypt.
	// The server never sees plaintext or any key — this is only a manifest
	// hint set by the sending client.
	EncMode string `json:"enc_mode,omitempty"`
}

type sendResult struct {
	MessageID string           `json:"message_id"`
	Subject   string           `json:"subject"`
	Delivered []map[string]any `json:"delivered"`
	Link      *linkJSON        `json:"link,omitempty"`
	CCOwner   string           `json:"cc_owner,omitempty"`
}

func normalizeSendRequest(req sendRequest) sendRequest {
	req.File = strings.TrimSpace(req.File)
	req.Note = strings.TrimSpace(req.Note)
	req.Subject = strings.TrimSpace(req.Subject)
	req.TTL = strings.ToLower(strings.TrimSpace(req.TTL))
	req.ReplyTo = strings.TrimSpace(req.ReplyTo)
	req.EncMode = strings.ToLower(strings.TrimSpace(req.EncMode))
	seen := map[string]bool{}
	to := make([]string, 0, len(req.To))
	for _, raw := range req.To {
		raw = strings.TrimSpace(raw)
		if parsed, err := mail.ParseAddress(raw); err == nil {
			raw = parsed.Address
		}
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == "" || seen[raw] {
			continue
		}
		seen[raw] = true
		to = append(to, raw)
	}
	req.To = to
	return req
}

func sendRequestHash(req sendRequest) (string, error) {
	canonical, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum), nil
}

func sendJSONBody(v any) ([]byte, error) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func writeSendBody(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func requestIdempotencyKey(r *http.Request) (string, bool, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", true, errors.New("Idempotency-Key must appear exactly once")
	}
	key := strings.TrimSpace(values[0])
	if key == "" || len(key) > store.MaxIdempotencyKeyBytes {
		return "", true, fmt.Errorf("Idempotency-Key must be 1-%d visible ASCII characters", store.MaxIdempotencyKeyBytes)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return "", true, errors.New("Idempotency-Key must contain only visible ASCII characters without spaces")
		}
	}
	return key, true, nil
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	idemKey, keyed, keyErr := requestIdempotencyKey(r)
	if keyErr != nil {
		errJSON(w, http.StatusBadRequest, "%v", keyErr)
		return
	}
	var req sendRequest
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	req = normalizeSendRequest(req)
	requestHash := ""
	if keyed {
		var err error
		requestHash, err = sendRequestHash(req)
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "fingerprint request: %v", err)
			return
		}
		// Collapse same-process duplicates before consulting the durable
		// reservation. A waiter wakes only after the first request has either
		// persisted its exact response or left a fail-closed pending record.
		flightKey := agent.ID + "\x00" + idemKey
		for {
			s.idemMu.Lock()
			ch, busy := s.idemFlight[flightKey]
			if !busy {
				ch = make(chan struct{})
				s.idemFlight[flightKey] = ch
				s.idemMu.Unlock()
				defer func() {
					s.idemMu.Lock()
					delete(s.idemFlight, flightKey)
					s.idemMu.Unlock()
					close(ch)
				}()
				break
			}
			s.idemMu.Unlock()
			select {
			case <-ch:
			case <-r.Context().Done():
				return
			}
		}
		record, created, err := s.st.BeginIdempotent(agent.ID, idemKey, requestHash)
		switch {
		case errors.Is(err, store.ErrIdempotencyConflict):
			errJSON(w, http.StatusConflict, "Idempotency-Key is already bound to a different send request")
			return
		case errors.Is(err, store.ErrLimit):
			errJSON(w, http.StatusTooManyRequests, "%v", err)
			return
		case err != nil:
			errJSON(w, http.StatusInternalServerError, "reserve idempotency key: %v", err)
			return
		case !created && record.Status == 0:
			errJSON(w, http.StatusConflict, "this Idempotency-Key has an unfinished prior request; its outcome cannot be replayed yet")
			return
		case !created:
			w.Header().Set("Idempotent-Replay", "true")
			writeSendBody(w, record.Status, record.Response)
			return
		}
	}

	res, status, err := s.performSend(agent, req)
	var response any = res
	if err != nil {
		response = map[string]string{"error": err.Error()}
	}
	if keyed {
		body, marshalErr := sendJSONBody(response)
		if marshalErr != nil {
			errJSON(w, http.StatusInternalServerError, "encode send response: %v", marshalErr)
			return
		}
		if completeErr := s.st.CompleteIdempotent(agent.ID, idemKey, requestHash, status, body); completeErr != nil {
			errJSON(w, http.StatusInternalServerError,
				"send finished but its idempotent response could not be persisted; retry only with the same key: %v", completeErr)
			return
		}
		writeSendBody(w, status, body)
		return
	}
	if err != nil {
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, status, res)
}

// performSend implements one send: resolve the file, mint a fresh link,
// deliver same-instance recipients straight to their inbox, relay the rest
// as real email. Shared by REST and MCP.
func (s *Server) performSend(agent store.Agent, req sendRequest) (*sendResult, int, error) {
	if len(req.To) == 0 {
		return nil, http.StatusBadRequest, errors.New("\"to\" requires at least one recipient")
	}
	if len(req.To) > 20 {
		return nil, http.StatusBadRequest, errors.New("at most 20 recipients per send")
	}
	if req.File == "" && strings.TrimSpace(req.Note) == "" {
		return nil, http.StatusBadRequest, errors.New("nothing to send: provide \"file\", \"note\", or both")
	}
	// Reject an unknown enc_mode: otherwise a garbage value would ride into the
	// offer and the recipient would silently save undecryptable ciphertext.
	if req.EncMode != "" && req.EncMode != proto.EncSymmetric && req.EncMode != proto.EncSealed {
		return nil, http.StatusBadRequest, fmt.Errorf("enc_mode must be %q, %q, or empty", proto.EncSymmetric, proto.EncSealed)
	}

	// Threading.
	var inReplyTo, references, replySubject string
	if req.ReplyTo != "" {
		orig, err := s.st.GetMessage(agent.ID, req.ReplyTo)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("reply_to: no message %q in your inbox", req.ReplyTo)
		}
		inReplyTo = orig.MessageID
		references = strings.TrimSpace(orig.References + " " + orig.MessageID)
		replySubject = orig.Subject
		if replySubject != "" && !strings.HasPrefix(strings.ToLower(replySubject), "re:") {
			replySubject = "Re: " + replySubject
		}
	}

	// Classify recipients (deduplicated — one delivery and one rate unit per
	// unique address).
	instance := s.st.Instance()
	var localAgents []store.Agent
	var remote []string
	var canonicalTo []string
	seen := map[string]bool{}
	for _, to := range req.To {
		raw := strings.TrimSpace(to)
		if raw == "" {
			continue
		}
		parsed, err := mail.ParseAddress(raw)
		if err != nil {
			if !strings.Contains(raw, "@") {
				return nil, http.StatusBadRequest, fmt.Errorf("recipient %q is not an address — for an agent on this instance use %q, or give a full email for a remote recipient", raw, strings.ToLower(raw)+"@"+instance)
			}
			return nil, http.StatusBadRequest, fmt.Errorf("recipient %q is not a valid email address", raw)
		}
		addr := strings.ToLower(strings.TrimSpace(parsed.Address))
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		canonicalTo = append(canonicalTo, addr)
		localpart, domain, ok := strings.Cut(addr, "@")
		if ok && domain == instance {
			resolved := s.resolveLocalRecipient(localpart)
			if len(resolved) == 0 {
				return nil, http.StatusBadRequest, fmt.Errorf("no agent %q on this instance", addr)
			}
			for _, la := range resolved {
				dup := false
				for _, have := range localAgents {
					if have.ID == la.ID {
						dup = true
						break
					}
				}
				if !dup {
					localAgents = append(localAgents, la)
				}
			}
			continue
		}
		remote = append(remote, addr)
	}
	if len(localAgents)+len(remote) == 0 {
		return nil, http.StatusBadRequest, errors.New("\"to\" requires at least one recipient")
	}

	if len(remote) > 0 {
		if !s.emailCapable() {
			return nil, http.StatusBadRequest, fmt.Errorf("this instance cannot send email (it can only deliver to local agents …@%s) — configure DOMAIN + OUTBOUND, or CONNECT to a host", instance)
		}
		if !agent.OwnerVerified {
			return nil, http.StatusForbidden, errors.New("outbound email requires a verified owner; open the verification link sent to your owner_email (or ask the operator)")
		}
	}

	// Recipients who unsubscribed are skipped (and reported); they consume
	// neither send rate nor a circle slot.
	var sendable, unsubscribed []string
	for _, addr := range remote {
		if s.st.IsSuppressed(addr) {
			unsubscribed = append(unsubscribed, addr)
		} else {
			sendable = append(sendable, addr)
		}
	}

	// Resolve the file reference and TTL before consuming quota — lookups
	// have no side effects, so a bad reference costs nothing.
	var sendFile *store.File
	var linkTTL time.Duration
	if req.File != "" {
		f, err := s.resolveFile(agent, req.File)
		if err != nil {
			return nil, http.StatusNotFound, err
		}
		sendFile = &f
		linkTTL, err = s.ttlFrom(req.TTL, s.cfg.DefaultTTL)
		if err != nil {
			return nil, http.StatusBadRequest, err
		}
	}

	// The recipient circle: every unique remote address the agent ever emails
	// counts against a small lifetime cap (the verified owner is exempt), so a
	// compromised or prompt-injected agent can reach at most a handful of
	// strangers. Claimed first among the spends because it is the only
	// releasable one — slots for sends that fail below are refunded.
	var newCircle []string
	if len(sendable) > 0 {
		circleAddrs := make([]string, 0, len(sendable))
		for _, a := range sendable {
			if agent.OwnerEmail == "" || !strings.EqualFold(a, agent.OwnerEmail) {
				circleAddrs = append(circleAddrs, a)
			}
		}
		var err error
		newCircle, err = s.st.ClaimHumanRecipients(agent.ID, circleAddrs, s.humanCircleMax(agent))
		if err != nil {
			if errors.Is(err, store.ErrCircleFull) {
				return nil, http.StatusForbidden, fmt.Errorf("%v — the operator can widen it: POST /v1/agents/%s/limits", err, agent.ID)
			}
			return nil, http.StatusInternalServerError, err
		}
	}

	// Rate limit one unit per unique recipient — after validation and before
	// the link is minted, so a rejected send leaves nothing behind (its rate
	// charge is refunded and its circle slots released).
	rateUnits := int64(len(localAgents) + len(sendable))
	if err := s.checkRateN(agent.ID, "sends", rateUnits, s.cfg.SendRate); err != nil {
		_ = s.st.ReleaseHumanRecipients(agent.ID, newCircle)
		return nil, http.StatusTooManyRequests, err
	}
	var link *store.Link
	keepSendSideEffects := false
	defer func() {
		if keepSendSideEffects {
			return
		}
		_, _ = s.st.IncrCounterN(agent.ID, "sends", -rateUnits)
		_ = s.st.ReleaseHumanRecipients(agent.ID, newCircle)
		if link != nil {
			_, _ = s.st.RevokeLink(link.Token)
		}
	}()

	// File → fresh ephemeral link.
	var filePart *proto.Part
	if sendFile != nil {
		l, err := s.st.CreateLink(agent.ID, sendFile.SHA256, sendFile.Name, sendFile.MIME, sendFile.Size, req.Once, linkTTL)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		link = &l
		p := proto.FilePart(l.Name, l.MIME, s.linkURL(l.Token), l.SHA256, l.Size,
			time.Unix(l.ExpiresAt, 0).UTC().Format(time.RFC3339), l.Once, req.EncMode)
		filePart = &p
	}

	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		switch {
		case replySubject != "":
			subject = replySubject
		case link != nil:
			subject = fmt.Sprintf("[AgentTransfer] %s (%s)", link.Name, humanSize(link.Size))
		default:
			subject = "[AgentTransfer] message from " + agent.Name
		}
	}

	msgID := store.NewID("msg")
	rfcMsgID := afmail.FormatRFCMessageID(msgID, s.st.Instance())

	manifest := proto.Manifest{V: proto.Version, From: agent.Email, MessageID: msgID}
	if req.ReplyTo != "" {
		manifest.InReplyTo = req.ReplyTo
	}
	if strings.TrimSpace(req.Note) != "" {
		manifest.Parts = append(manifest.Parts, proto.TextPart(req.Note))
	}
	if filePart != nil {
		manifest.Parts = append(manifest.Parts, *filePart)
	}
	manifestJSON, _ := json.Marshal(manifest)

	res := &sendResult{MessageID: msgID, Subject: subject, Delivered: []map[string]any{}}
	if link != nil {
		lj := s.linkJSON(*link)
		res.Link = &lj
	}

	// Local fast path: same-instance recipients skip SMTP entirely. Each
	// recipient's accept policy decides whether the message lands in the main
	// inbox, is held in quarantine, or (for "closed") is refused outright.
	var deliveryErr error
	for _, la := range localAgents {
		deliver, quarantined := s.decideInbound(la, agent.Email, true)
		if !deliver {
			res.Delivered = append(res.Delivered, map[string]any{"to": la.Email, "via": "rejected", "reason": "recipient only accepts known senders"})
			continue
		}
		lm, err := s.st.AddMessage(store.Message{
			AgentID: la.ID, From: agent.Email, To: canonicalTo, Subject: subject,
			Text: strings.TrimSpace(req.Note), MessageID: rfcMsgID,
			InReplyTo: inReplyTo, References: references,
			Manifest: string(manifestJSON), DKIM: "local", SPF: "local",
			Quarantined: quarantined,
		})
		if err != nil {
			deliveryErr = err
			reason := "recipient inbox unavailable"
			if errors.Is(err, store.ErrInboxFull) {
				reason = "recipient mailbox full"
			}
			res.Delivered = append(res.Delivered, map[string]any{"to": la.Email, "via": "rejected", "reason": reason})
			continue
		}
		keepSendSideEffects = true
		// A quarantined message is held out of the main inbox, so it must not
		// wake a long-poll or fire a webhook — that would defeat quarantine as a
		// spam control. It's still receipted (it did arrive) and readable via
		// GET /v1/inbox?quarantined=1.
		if !quarantined {
			s.hub.notify(la.ID)
			s.enqueueWebhooks(la.ID, "message.received", lm.ID, agent.Email)
		}
		s.appendReceipt(agent.Email, receipt.ActionSent, shaOf(link), sizeOf(link), la.Email, msgID)
		s.appendReceipt(la.Email, receipt.ActionReceived, shaOf(link), sizeOf(link), agent.Email, msgID)
		via := "inbox"
		if quarantined {
			via = "quarantined"
		}
		res.Delivered = append(res.Delivered, map[string]any{"to": la.Email, "via": via})
	}

	// Remote: one real email PER recipient through the relay, each carrying
	// its own unsubscribe link (a shared body can't personalize suppression).
	ccOwner := req.CCOwner || agent.AlwaysCCOwner
	var cc []string
	if ccOwner {
		switch {
		case agent.OwnerEmail == "":
			res.CCOwner = "skipped (agent has no owner_email)"
		case !agent.OwnerVerified:
			// The CC rides the relay like any outbound email, so it needs the
			// same verified owner — otherwise an unverified signup could relay
			// mail to an arbitrary owner_email via local-only sends.
			res.CCOwner = "skipped (owner not verified)"
		default:
			alreadyIncluded := false
			for _, recipient := range sendable {
				if strings.EqualFold(recipient, agent.OwnerEmail) {
					alreadyIncluded = true
					break
				}
			}
			if alreadyIncluded {
				res.CCOwner = "already included as recipient"
			} else {
				cc = append(cc, agent.OwnerEmail)
			}
		}
	}
	if len(sendable) > 0 || len(cc) > 0 {
		if !s.emailCapable() {
			if ccOwner && res.CCOwner == "" {
				res.CCOwner = "skipped (no outbound email path configured)"
			}
		} else {
			sendOne := func(to []string, unsubURL string) error {
				m := &afmail.Message{
					FromName: agent.Name, From: agent.Email,
					To: to, Subject: subject,
					Text:      s.renderBody(agent, req.Note, link, unsubURL),
					MessageID: rfcMsgID, InReplyTo: inReplyTo, References: references,
					Manifest: manifestJSON, ManifestName: proto.Filename,
				}
				raw, err := m.Build()
				if err != nil {
					return err
				}
				return s.sendRaw(agent.Email, to, raw)
			}
			var failedCircle []string
			var lastErr error
			delivered := 0
			for _, to := range sendable {
				if err := sendOne([]string{to}, s.unsubscribeURL(to)); err != nil {
					lastErr = err
					log.Printf("send: relay to %s (from %s) failed: %v", to, agent.Email, err)
					res.Delivered = append(res.Delivered, map[string]any{"to": to, "via": "error", "error": err.Error()})
					for _, n := range newCircle {
						if n == to {
							failedCircle = append(failedCircle, to)
						}
					}
					continue
				}
				delivered++
				keepSendSideEffects = true
				s.appendReceipt(agent.Email, receipt.ActionSent, shaOf(link), sizeOf(link), to, msgID)
				res.Delivered = append(res.Delivered, map[string]any{"to": to, "via": "email"})
			}
			// The owner's copy carries no unsubscribe link — the owner's lever
			// is verification/limits, not suppression.
			if len(cc) > 0 {
				if err := sendOne(cc, ""); err != nil {
					deliveryErr = err
					res.CCOwner = "failed: " + err.Error()
				} else {
					keepSendSideEffects = true
					res.CCOwner = "sent to " + agent.OwnerEmail
				}
			}
			// A recipient whose send failed must not consume a circle slot
			// forever (typo'd addresses would burn the cap).
			if len(failedCircle) > 0 {
				_ = s.st.ReleaseHumanRecipients(agent.ID, failedCircle)
			}
			if len(sendable) > 0 && delivered == 0 && !keepSendSideEffects {
				deliveryErr = fmt.Errorf("email send failed: %w", lastErr)
			}
		}
	}
	for _, addr := range unsubscribed {
		res.Delivered = append(res.Delivered, map[string]any{"to": addr, "via": "suppressed"})
	}
	if !keepSendSideEffects {
		// The deferred rollback refunds rate/circle state and revokes the fresh
		// link. Do not return a URL that is deliberately being invalidated.
		res.Link = nil
		if deliveryErr != nil {
			status := http.StatusBadGateway
			if errors.Is(deliveryErr, store.ErrInboxFull) {
				status = http.StatusInsufficientStorage
			}
			return nil, status, deliveryErr
		}
	}

	s.metrics.sends.Add(1)
	return res, http.StatusCreated, nil
}

func shaOf(l *store.Link) string {
	if l == nil {
		return ""
	}
	return l.SHA256
}

func sizeOf(l *store.Link) int64 {
	if l == nil {
		return 0
	}
	return l.Size
}

func (s *Server) renderBody(agent store.Agent, note string, link *store.Link, unsubURL string) string {
	var b strings.Builder
	if strings.TrimSpace(note) != "" {
		b.WriteString(strings.TrimSpace(note))
		b.WriteString("\n\n")
	}
	if link != nil {
		fmt.Fprintf(&b, "File: %s (%s)\nDownload: %s\nExpires: %s\nsha256: %s\n",
			link.Name, humanSize(link.Size), s.linkURL(link.Token),
			time.Unix(link.ExpiresAt, 0).UTC().Format(time.RFC3339), link.SHA256)
		if link.Once {
			b.WriteString("This link is single-download: it burns after the first complete fetch.\n")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "--\nSent by agent %s via AgentTransfer (verify integrity with the sha256 above)\n", agent.Email)
	if unsubURL != "" {
		fmt.Fprintf(&b, "Stop receiving mail from agents on this instance: %s\n", unsubURL)
	}
	return b.String()
}

// unsubscribeURL builds the per-recipient suppression link that rides in
// every human-bound email footer.
func (s *Server) unsubscribeURL(addr string) string {
	return s.BaseURL() + "/unsubscribe?e=" + url.QueryEscape(addr) + "&t=" + s.st.UnsubscribeToken(addr)
}

// handleUnsubscribe (GET) shows a confirm page — like verification, the GET
// consumes nothing so link prefetchers can't unsubscribe (or DoS-suppress) an
// address; only the explicit POST does.
func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	addr := strings.TrimSpace(r.URL.Query().Get("e"))
	tok := strings.TrimSpace(r.URL.Query().Get("t"))
	if addr == "" || !s.st.CheckUnsubscribeToken(addr, tok) {
		http.Error(w, "invalid unsubscribe link", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s.st.IsSuppressed(addr) {
		_ = s.tmpl.ExecuteTemplate(w, "unsubscribed.html", map[string]any{"Addr": addr})
		return
	}
	_ = s.tmpl.ExecuteTemplate(w, "unsubscribe.html", map[string]any{
		"Addr":   addr,
		"Action": "/unsubscribe?e=" + url.QueryEscape(addr) + "&t=" + url.QueryEscape(tok),
	})
}

// handleUnsubscribeConfirm (POST) suppresses the address for good.
func (s *Server) handleUnsubscribeConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	addr := strings.TrimSpace(r.URL.Query().Get("e"))
	tok := strings.TrimSpace(r.URL.Query().Get("t"))
	if addr == "" || !s.st.CheckUnsubscribeToken(addr, tok) {
		http.Error(w, "invalid unsubscribe link", http.StatusNotFound)
		return
	}
	if err := s.st.Suppress(addr); err != nil {
		http.Error(w, "unsubscribe failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "unsubscribed.html", map[string]any{"Addr": addr})
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---- inbox ----

func (s *Server) messageJSON(m store.Message) map[string]any {
	out := map[string]any{
		"id": m.ID, "from": m.From, "to": m.To, "subject": m.Subject, "text": m.Text,
		"message_id": m.MessageID, "read": m.Read,
		"dkim": m.DKIM, "spf": m.SPF,
		"attachments": m.Attachments,
		"received_at": time.Unix(m.ReceivedAt, 0).UTC().Format(time.RFC3339),
	}
	out["sender"] = senderIdentity(m.DKIM, m.From)
	if m.Quarantined {
		out["quarantined"] = true
	}
	if m.InReplyTo != "" {
		out["in_reply_to"] = m.InReplyTo
	}
	if m.References != "" {
		out["references"] = m.References
	}
	if m.Manifest != "" {
		var man proto.Manifest
		if err := json.Unmarshal([]byte(m.Manifest), &man); err == nil {
			out["manifest"] = man
			if fp := man.FirstFile(); fp != nil {
				offer := map[string]any{
					"name":       fp.File.Name,
					"mime":       fp.File.MIMEType,
					"url":        fp.File.URI,
					"sha256":     fp.MetaString(proto.MetaSHA256),
					"size":       fp.MetaInt64(proto.MetaSize),
					"expires_at": fp.MetaString(proto.MetaExpiresAt),
					// Burn-after-read links must be fetched knowingly — the
					// download consumes them.
					"once": fp.MetaBool(proto.MetaOnce),
				}
				// Client-encrypted file: tell the recipient it must decrypt
				// (symmetric = supply the out-of-band key; sealed = use its
				// own identity). Absent for plaintext.
				if enc := fp.MetaString(proto.MetaEncMode); enc != "" {
					offer["enc_mode"] = enc
				}
				// Only auto-trust offers with authenticated provenance.
				offer["trusted"] = m.DKIM == "pass" || m.DKIM == "local"
				out["offer"] = offer
			}
		}
	}
	return out
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	q := r.URL.Query()
	unread := q.Get("unread") == "1" || q.Get("unread") == "true"
	limit, _ := strconv.Atoi(q.Get("limit"))
	var msgs []store.Message
	var err error
	if q.Get("quarantined") == "1" || q.Get("quarantined") == "true" {
		// The quarantine bucket: messages held back by the accept policy.
		msgs, err = s.st.ListQuarantine(agent.ID, limit)
	} else {
		msgs, err = s.st.ListInbox(agent.ID, unread, q.Get("thread"), limit)
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, s.messageJSON(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

func (s *Server) handleInboxWait(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	timeout := 30 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		if secs, err := strconv.Atoi(t); err == nil && secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}

	ch, cancel := s.hub.subscribe(agent.ID)
	defer cancel()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		msgs, err := s.st.ListInbox(agent.ID, true, "", 0)
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if len(msgs) > 0 {
			out := make([]map[string]any, 0, len(msgs))
			for _, m := range msgs {
				out = append(out, s.messageJSON(m))
			}
			writeJSON(w, http.StatusOK, map[string]any{"messages": out})
			return
		}
		select {
		case <-ch:
			// New mail signal: loop and fetch.
		case <-deadline.C:
			writeJSON(w, http.StatusOK, map[string]any{"messages": []any{}})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	m, err := s.st.GetMessage(agent.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no such message")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, s.messageJSON(m))
}

func (s *Server) handleMarkRead(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	if err := s.st.MarkRead(agent.ID, r.PathValue("id")); err != nil {
		errJSON(w, http.StatusNotFound, "no such message")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"read": true})
}

// ---- upload requests ----

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req struct {
		Note string `json:"note"`
		TTL  string `json:"ttl"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	ttl, err := s.ttlFrom(req.TTL, s.cfg.MaxTTL)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	u, err := s.st.CreateUploadRequest(agent.ID, req.Note, ttl)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_url": s.BaseURL() + "/u/" + u.Token,
		"token":      u.Token,
		"expires_at": time.Unix(u.ExpiresAt, 0).UTC().Format(time.RFC3339),
	})
}

// ---- receipts ----

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rs, err := s.st.ListReceipts(agent.Email, limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"instance":       s.st.Instance(),
		"receipt_pubkey": receipt.FormatPublicKey(s.st.PublicKey()),
		"receipts":       rs,
	})
}

// handleReceiptsExport streams the full instance chain as JSONL (admin only) —
// the verifiable, portable evidence log.
func (s *Server) handleReceiptsExport(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	rs, err := s.st.ListReceipts("", 0)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/jsonl")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Receipt-Pubkey", receipt.FormatPublicKey(s.st.PublicKey()))
	enc := json.NewEncoder(w)
	for _, rec := range rs {
		_ = enc.Encode(rec)
	}
}

// handleAdminStorage (admin) is the operator's storage dashboard: volume and
// disk-guard state plus the top consumers by distinct logical transfer bytes —
// abuse cleanup starts with being able to SEE who holds the disk.
func (s *Server) handleAdminStorage(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	agents, err := s.st.TopStorageConsumers(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	stored, err := s.st.StoredBytes()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "read stored bytes: %v", err)
		return
	}
	apps, err := s.st.TopAppStorageConsumers(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "read app storage: %v", err)
		return
	}
	appStorage := map[string]any{"domain": s.cfg.AppDomain, "source_agents": apps}
	if appRootBytes, walkErr := directoryBytes(s.cfg.AppBuildRoot); walkErr == nil {
		appStorage["build_root_bytes"] = appRootBytes
	} else {
		appStorage["app_root_observation_error"] = walkErr.Error()
	}
	if s.appRunner != nil {
		var persistentBytes int64
		observationErrors := 0
		if histories, historyErr := s.st.AppsWithContainerHistory(); historyErr == nil {
			for _, app := range histories {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				status, statusErr := s.appRunner.Status(ctx, app.ID)
				cancel()
				if statusErr != nil {
					observationErrors++
					continue
				}
				total, ok := addStorageBytes(persistentBytes, status.DataBytes)
				if !ok {
					observationErrors++
					continue
				}
				persistentBytes = total
			}
		} else {
			observationErrors++
		}
		appStorage["persistent_data_bytes"] = persistentBytes
		appStorage["persistent_data_observation_errors"] = observationErrors
	}
	free, total, reserve := s.st.DiskStats()
	writeJSON(w, http.StatusOK, map[string]any{
		"volume": map[string]any{
			"total":           total,
			"free":            free,
			"reserve":         reserve,
			"guard_active":    reserve > 0,
			"uploads_refused": s.st.DiskFull(),
		},
		"stored_bytes": stored, // physical (deduplicated) blob bytes
		"agents":       agents, // logical transfer bytes per agent, biggest first
		"apps":         appStorage,
	})
}

// ---- meta ----

func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"name":           "agenttransfer",
		"version":        Version,
		"instance":       s.st.Instance(),
		"receipt_pubkey": receipt.FormatPublicKey(s.st.PublicKey()),
		"max_file_size":  s.cfg.MaxFileSize,
		"default_ttl":    s.cfg.DefaultTTL.String(),
		"max_ttl":        s.cfg.MaxTTL.String(),
		"open_signup":    s.cfg.OpenSignup,
		"email_enabled":  s.emailCapable(),
		"protocols":      map[string]any{"manifest": proto.Version, "uri_file_parts": true},
		"endpoints":      map[string]string{"api": s.BaseURL() + "/v1", "mcp": s.BaseURL() + "/mcp"},
	}
	if s.cfg.AppDomain != "" {
		readiness := s.appHostingStatus(r.Context())
		staticReady, containersReady := s.advertisedAppHosting(r.Context())
		out["app_hosting"] = map[string]any{
			"configured":                        true,
			"domain":                            s.cfg.AppDomain,
			"url_pattern":                       "https://{agent-slug}." + s.cfg.AppDomain,
			"human_email_verification_required": true,
			"static":                            staticReady,
			"containers":                        containersReady,
			"storage_quota":                     s.cfg.AppStorageQuota,
			"readiness": map[string]bool{
				"runner":       readiness.RunnerReady,
				"wildcard_dns": readiness.WildcardDNSReady,
			},
		}
	}
	// Advertise the abuse contact when the operator has stood one up (an
	// agent named "abuse" — the name is reserved from open signup).
	if s.cfg.EmailEnabled() {
		if a, err := s.st.AgentByName("abuse"); err == nil {
			out["abuse"] = a.Email
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Agents that ask for a text form of the front page get the llms.txt —
	// browsers always lead with text/html and keep the human page.
	if wantsMarkdown(r) {
		s.handleLLMs(w, r)
		return
	}
	staticReady, containersReady := s.advertisedAppHosting(r.Context())
	appDomain := ""
	if staticReady {
		appDomain = s.cfg.AppDomain
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "index.html", map[string]any{
		"Instance":         s.st.Instance(),
		"OpenSignup":       s.cfg.OpenSignup,
		"Base":             s.BaseURL(),
		"AppDomain":        appDomain,
		"ContainerHosting": containersReady,
	})
}

func (s *Server) handleLaunch(w http.ResponseWriter, r *http.Request) {
	staticReady, containersReady := s.advertisedAppHosting(r.Context())
	if !staticReady {
		http.Error(w, "app hosting is not enabled on this instance", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = s.tmpl.ExecuteTemplate(w, "launch.html", map[string]any{
		"Instance":         s.st.Instance(),
		"Base":             s.BaseURL(),
		"AppDomain":        s.cfg.AppDomain,
		"ContainerHosting": containersReady,
	})
}

func (s *Server) handleLaunchAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name != "agent-hosting-hero.webp" && name != "agent-hosting-detail.webp" && name != "agent-hosting-hero.jpg" {
		http.NotFound(w, r)
		return
	}
	data, err := templateFS.ReadFile("static/launch/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType := "image/webp"
	if strings.HasSuffix(name, ".jpg") {
		contentType = "image/jpeg"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(data)
}

// Version is stamped at build time via -ldflags; keep a sane default.
var Version = "0.7.0-dev"
