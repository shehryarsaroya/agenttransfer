package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	afmail "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// The human side of a hosted instance: sign in with an email link (or a
// password, for accounts such as directory reviewers that can't receive mail),
// see the drive every connected AI shares, connect and disconnect AIs, and
// mint API keys for agents that run on their own computers (Muse, Claude Code,
// Codex, OpenClaw). OAuth consent (oauth.go) reuses the same session.

const (
	sessionCookie  = "at_session"
	sessionTTL     = 30 * 24 * time.Hour
	loginLinkTTL   = 20 * time.Minute
	webAgentTag    = "web"
	minPasswordLen = 10
)

func (s *Server) secureCookies() bool { return strings.HasPrefix(s.BaseURL(), "https://") }

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secureCookies(),
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// currentPerson resolves the signed-in person, if any.
func (s *Server) currentPerson(r *http.Request) (store.Person, store.WebSession, bool) {
	if !s.cfg.Accounts {
		return store.Person{}, store.WebSession{}, false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return store.Person{}, store.WebSession{}, false
	}
	ws, err := s.st.LookupWebSession(c.Value)
	if err != nil {
		return store.Person{}, store.WebSession{}, false
	}
	p, err := s.st.PersonByID(ws.PersonID)
	if err != nil {
		return store.Person{}, store.WebSession{}, false
	}
	return p, ws, true
}

// safeNext keeps post-login redirects on this site.
func safeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/account"
	}
	return next
}

// render executes a site template with the common page data.
func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Base"] = s.BaseURL()
	data["Domain"] = s.st.Instance()
	data["Year"] = time.Now().Year()
	data["Accounts"] = s.cfg.Accounts
	if s.cfg.SupportEmail != "" {
		data["Support"] = s.cfg.SupportEmail
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https: http://localhost:* http://127.0.0.1:*")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

func (s *Server) accountsOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Accounts {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// ---- sign in ----

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, _, ok := s.currentPerson(r); ok {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	s.render(w, "login.html", map[string]any{"Next": next, "Mode": r.URL.Query().Get("mode")})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.PostFormValue("next"))
	email, err := canonicalMailbox(r.PostFormValue("email"))
	if err != nil {
		s.render(w, "login.html", map[string]any{"Next": next, "Error": "Enter a valid email address.", "Email": r.PostFormValue("email")})
		return
	}
	if !s.signupLimiter.allow("login:" + s.clientIP(r)) {
		s.render(w, "login.html", map[string]any{"Next": next, "Email": email, "Error": "Too many sign-in attempts from this network. Try again in a while."})
		return
	}
	if pw := r.PostFormValue("password"); pw != "" {
		p, perr := s.st.PersonByEmail(email)
		var hash string
		if perr == nil {
			hash, _ = s.st.PasswordHash(p.ID)
		}
		if perr != nil || hash == "" || !store.CheckPassword(hash, pw) {
			s.render(w, "login.html", map[string]any{"Next": next, "Email": email, "Mode": "password",
				"Error": "That email and password don't match. You can also sign in with an email link."})
			return
		}
		s.startSession(w, r, p, next)
		return
	}
	if n, _ := s.st.CountRecentLoginTokens(email, time.Now().Add(-time.Hour).Unix()); n >= 5 {
		s.render(w, "login.html", map[string]any{"Next": next, "Email": email, "Error": "We've sent several links to this address in the last hour. Check your inbox (and spam), or try again later."})
		return
	}
	tok, err := s.st.CreateLoginToken(email, next, loginLinkTTL)
	if err != nil {
		s.render(w, "login.html", map[string]any{"Next": next, "Email": email, "Error": "Something went wrong. Please try again."})
		return
	}
	link := s.BaseURL() + "/login/verify?t=" + url.QueryEscape(tok)
	data := map[string]any{"Email": email}
	if err := s.sendLoginEmail(email, link); err != nil {
		log.Printf("login: send link to %s: %v", email, err)
		if s.cfg.DevLoginLinks {
			data["DevLink"] = link
		} else {
			s.render(w, "login.html", map[string]any{"Next": next, "Email": email, "Error": "We couldn't send the email right now. Please try again shortly."})
			return
		}
	} else if s.cfg.DevLoginLinks {
		data["DevLink"] = link
	}
	s.render(w, "login_sent.html", data)
}

func (s *Server) sendLoginEmail(to, link string) error {
	if !s.emailCapable() {
		return errors.New("no outbound email configured")
	}
	from := "no-reply@" + s.st.Instance()
	m := &afmail.Message{
		FromName: "AgentTransfer",
		From:     from,
		To:       []string{to},
		Subject:  "Your AgentTransfer sign-in link",
		Text: fmt.Sprintf("Sign in to AgentTransfer:\n\n  %s\n\n"+
			"The link works once and expires in 20 minutes.\n\n"+
			"If you didn't ask for it, ignore this email — nothing happens without a click.\n", link),
		MessageID: afmail.FormatRFCMessageID(store.NewID("msg"), s.st.Instance()),
	}
	raw, err := m.Build()
	if err != nil {
		return err
	}
	return s.sendRaw(from, []string{to}, raw)
}

// handleLoginVerifyPage shows a confirm button: mail scanners prefetch links,
// so a GET never signs anyone in.
func (s *Server) handleLoginVerifyPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok := r.URL.Query().Get("t")
	email, _, err := s.st.PeekLoginToken(tok)
	if err != nil {
		s.render(w, "message.html", map[string]any{"Title": "Link expired", "Message": "This sign-in link has expired or was already used.", "Action": "/login", "ActionLabel": "Get a new link"})
		return
	}
	s.render(w, "login_confirm.html", map[string]any{"Email": email, "Token": tok})
}

func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	email, next, err := s.st.ConsumeLoginToken(r.PostFormValue("t"))
	if err != nil {
		s.render(w, "message.html", map[string]any{"Title": "Link expired", "Message": "This sign-in link has expired or was already used.", "Action": "/login", "ActionLabel": "Get a new link"})
		return
	}
	p, err := s.st.PersonByEmail(email)
	isNew := false
	if errors.Is(err, store.ErrNotFound) {
		p, err = s.st.CreateVerifiedPerson(email, "")
		isNew = true
	}
	if err != nil {
		s.render(w, "message.html", map[string]any{"Title": "Couldn't sign in", "Message": "We couldn't create your account. Please try again."})
		return
	}
	if !p.Verified() {
		// A person first created by an agent ("as" signup) is now proven.
		_ = s.st.MarkPersonVerified(p.ID)
		p, _ = s.st.PersonByID(p.ID)
	}
	if isNew {
		next = "/welcome?next=" + url.QueryEscape(safeNext(next))
	}
	s.startSession(w, r, p, next)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, p store.Person, next string) {
	tok, _, err := s.st.CreateWebSession(p.ID, sessionTTL)
	if err != nil {
		s.render(w, "message.html", map[string]any{"Title": "Couldn't sign in", "Message": "Please try again."})
		return
	}
	s.setSessionCookie(w, tok, sessionTTL)
	if strings.HasPrefix(next, "/welcome") {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.st.DeleteWebSession(c.Value)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- first run: pick a handle ----

func (s *Server) handleWelcome(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := s.currentPerson(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	next := safeNext(r.FormValue("next"))
	if r.Method == http.MethodPost {
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
			http.Error(w, "form expired — reload and try again", http.StatusForbidden)
			return
		}
		handle := strings.ToLower(strings.TrimSpace(r.PostFormValue("handle")))
		if handle != "" && handle != p.Handle {
			if err := s.st.RenamePerson(p.ID, handle); err != nil {
				s.render(w, "welcome.html", map[string]any{"Person": p, "Next": next, "CSRF": sess.CSRF, "Error": err.Error(), "Handle": handle})
				return
			}
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.render(w, "welcome.html", map[string]any{"Person": p, "Next": next, "CSRF": sess.CSRF, "Handle": p.Handle})
}

// ---- account ----

type connectedAI struct {
	Agent     store.Agent
	Client    string
	Host      string
	Via       string // "OAuth" or "API key"
	LastUsed  string
	Connected string
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	p, sess, ok := s.currentPerson(r)
	if !ok {
		http.Redirect(w, r, "/login?next=/account", http.StatusFound)
		return
	}
	s.renderAccount(w, r, p, sess, nil)
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession, extra map[string]any) {
	drive, err := s.st.DriveForPerson(p.ID)
	if err != nil {
		s.render(w, "message.html", map[string]any{"Title": "Account unavailable", "Message": err.Error()})
		return
	}
	files, _ := s.st.ListFiles(drive.ID)
	used, _ := s.st.StorageUsed(drive.ID)
	quota := s.quotaFor(drive)
	agents, _ := s.st.AgentsByPerson(p.ID, false)
	grants, _ := s.st.GrantsByPerson(p.ID)
	byAgent := map[string]store.OAuthGrant{}
	for _, g := range grants {
		byAgent[g.AgentID] = g
	}
	var conns []connectedAI
	for _, a := range agents {
		c := connectedAI{Agent: a, Via: "API key", Connected: time.Unix(a.CreatedAt, 0).UTC().Format("Jan 2, 2006")}
		tag := strings.TrimPrefix(a.Name, p.Handle+"+")
		if tag == webAgentTag {
			continue
		}
		if g, ok := byAgent[a.ID]; ok {
			c.Via = "OAuth"
			if cl, err := s.st.OAuthClientByID(g.ClientID); err == nil {
				c.Client, c.Host = cl.Name, clientHost(cl)
			}
			if g.LastUsedAt > 0 {
				c.LastUsed = humanAgo(time.Unix(g.LastUsedAt, 0))
			}
		}
		conns = append(conns, c)
	}
	sort.SliceStable(conns, func(i, j int) bool { return conns[i].Agent.CreatedAt > conns[j].Agent.CreatedAt })
	hasPW := false
	if h, err := s.st.PasswordHash(p.ID); err == nil && h != "" {
		hasPW = true
	}
	pct := 0
	if quota > 0 {
		pct = int(used * 100 / quota)
	}
	data := map[string]any{
		"Person": p, "CSRF": sess.CSRF, "Files": files, "Used": humanSize(used), "Quota": roundSize(quota),
		"UsedPct": pct, "Connections": conns, "HasPassword": hasPW, "Plan": s.st.PersonPlan(p.ID),
		"MCP": s.mcpResource(), "Remote": s.st.Remote(), "MaxFile": roundSize(s.cfg.MaxFileSize),
		"PersonAddress": p.Handle + "@" + s.st.Instance(),
	}
	for k, v := range extra {
		data[k] = v
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "account.html", data)
}

func humanAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// accountPost wraps account form handlers with session + CSRF checks.
func (s *Server) accountPost(next func(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, sess, ok := s.currentPerson(r)
		if !ok {
			http.Redirect(w, r, "/login?next=/account", http.StatusSeeOther)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
			http.Error(w, "form expired — reload the page and try again", http.StatusForbidden)
			return
		}
		next(w, r, p, sess)
	}
}

func (s *Server) handleCreateAgentKey(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession) {
	tag := strings.ToLower(strings.TrimSpace(r.PostFormValue("tag")))
	if tag == webAgentTag || tag == store.DriveTag {
		s.renderAccount(w, r, p, sess, map[string]any{"KeyError": fmt.Sprintf("%q is reserved — pick another name", tag)})
		return
	}
	agent, key, err := s.st.CreateApprovedAgentForPerson(p, tag)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, store.ErrNameTaken) {
			msg = fmt.Sprintf("you already have an agent called %q", tag)
		}
		s.renderAccount(w, r, p, sess, map[string]any{"KeyError": msg})
		return
	}
	s.renderAccount(w, r, p, sess, map[string]any{"NewKey": key, "NewAgent": agent.Email})
}

func (s *Server) handleRemoveAgent(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession) {
	agent, err := s.st.AgentByID(r.PathValue("id"))
	if err != nil || agent.PersonID != p.ID || agent.IsDrive() {
		http.Error(w, "no such agent", http.StatusNotFound)
		return
	}
	_ = s.st.RevokeAgentTokens(agent.ID)
	if _, tokens, err := s.st.DeleteAgent(agent.ID); err == nil {
		for _, t := range tokens {
			s.sever(t)
		}
		s.appendReceipt(agent.Email, receipt.ActionDeleted, "", 0, "agent:"+agent.Name, "")
	}
	http.Redirect(w, r, "/account#connections", http.StatusSeeOther)
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession) {
	pw := r.PostFormValue("password")
	if r.PostFormValue("clear") == "1" {
		_ = s.st.SetPassword(p.ID, "")
		s.renderAccount(w, r, p, sess, map[string]any{"PasswordMsg": "Password removed — sign in with email links."})
		return
	}
	if len(pw) < minPasswordLen {
		s.renderAccount(w, r, p, sess, map[string]any{"PasswordMsg": fmt.Sprintf("Use at least %d characters.", minPasswordLen)})
		return
	}
	h, err := store.HashPassword(pw)
	if err == nil {
		err = s.st.SetPassword(p.ID, h)
	}
	if err != nil {
		s.renderAccount(w, r, p, sess, map[string]any{"PasswordMsg": "Couldn't save the password."})
		return
	}
	s.renderAccount(w, r, p, sess, map[string]any{"PasswordMsg": "Password set."})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request, p store.Person, sess store.WebSession) {
	if strings.TrimSpace(strings.ToLower(r.PostFormValue("confirm"))) != p.Handle {
		s.renderAccount(w, r, p, sess, map[string]any{"DeleteMsg": "Type your handle exactly to confirm."})
		return
	}
	agents, _ := s.st.AgentsByPerson(p.ID, false)
	for _, a := range agents {
		_ = s.st.RevokeAgentTokens(a.ID)
	}
	if err := s.st.DeletePerson(p.ID); err != nil {
		s.renderAccount(w, r, p, sess, map[string]any{"DeleteMsg": "Couldn't delete the account: " + err.Error()})
		return
	}
	s.clearSessionCookie(w)
	s.render(w, "message.html", map[string]any{"Title": "Account deleted", "Message": "Your account, connected agents and files are gone. Stored bytes are removed from storage within minutes."})
}

// ---- the browser's drive: the REST handlers, acting as handle+web ----

// webAgent returns (creating on first use) the person's browser agent.
func (s *Server) webAgent(p store.Person) (store.Agent, error) {
	if a, err := s.st.AgentByName(p.Handle + "+" + webAgentTag); err == nil && a.PersonID == p.ID {
		return a, nil
	}
	a, _, err := s.st.CreateApprovedAgentForPerson(p, webAgentTag)
	if errors.Is(err, store.ErrNameTaken) {
		a, err = s.st.AgentByName(p.Handle + "+" + webAgentTag)
	}
	return a, err
}

// webAPI lets the account page call REST handlers with its session cookie.
// State-changing requests must carry the session's CSRF token in X-CSRF-Token.
func (s *Server) webAPI(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, sess, ok := s.currentPerson(r)
		if !ok {
			errJSON(w, http.StatusUnauthorized, "sign in first")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead &&
			subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
			errJSON(w, http.StatusForbidden, "missing or stale CSRF token — reload the page")
			return
		}
		agent, err := s.webAgent(p)
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		next(w, r, agent)
	}
}

// handleAdminCreateAccount (operator) creates a verified account, optionally
// with a password and plan — for directory reviewer accounts, which must sign
// in without email links.
func (s *Server) handleAdminCreateAccount(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Handle   string `json:"handle"`
		Password string `json:"password"`
		Plan     string `json:"plan"`
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
	p, err := s.st.PersonByEmail(email)
	if errors.Is(err, store.ErrNotFound) {
		p, err = s.st.CreateVerifiedPerson(email, req.Handle)
	}
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if !p.Verified() {
		_ = s.st.MarkPersonVerified(p.ID)
	}
	if req.Password != "" {
		if len(req.Password) < minPasswordLen {
			errJSON(w, http.StatusBadRequest, "password must be at least %d characters", minPasswordLen)
			return
		}
		h, err := store.HashPassword(req.Password)
		if err == nil {
			err = s.st.SetPassword(p.ID, h)
		}
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}
	if req.Plan != "" {
		if err := s.st.SetPersonPlan(p.ID, req.Plan); err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"person_id": p.ID, "handle": p.Handle, "email": p.Email,
		"address": p.Handle + "@" + s.st.Instance(), "password_set": req.Password != ""})
}
