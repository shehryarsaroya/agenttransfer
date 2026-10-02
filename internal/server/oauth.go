package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// OAuth 2.1 authorization server for MCP clients (ChatGPT, Claude, Muse,
// Gemini, …). Public clients only (PKCE S256, token_endpoint_auth_method
// "none"); clients identify themselves with a Client ID Metadata Document
// (an https client_id URL, preferred by ChatGPT and Claude) or by dynamic
// registration. Consent binds the client to one agent of the person's fleet
// (handle+chatgpt), so every token acts as a concrete, revocable identity.

const (
	accessTokenTTL  = time.Hour
	refreshTokenTTL = 90 * 24 * time.Hour
	cimdMaxBytes    = 16 << 10
	cimdFreshFor    = time.Hour
	cimdStaleOK     = 24 * time.Hour
)

func (s *Server) issuer() string      { return s.BaseURL() }
func (s *Server) mcpResource() string { return s.BaseURL() + "/mcp" }

// validResource accepts the MCP resource in the canonical forms clients send
// (Claude lowercases and strips trailing slashes; ChatGPT echoes metadata),
// plus the bare origin for REST-scoped tokens.
func (s *Server) validResource(res string) bool {
	if res == "" {
		return true
	}
	norm := func(v string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(v)), "/") }
	r := norm(res)
	return r == norm(s.mcpResource()) || r == norm(s.BaseURL())
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.mcpResource(),
		"authorization_servers":    []string{s.issuer()},
		"scopes_supported":         []string{mcpScope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "AgentTransfer",
		"resource_documentation":   s.BaseURL() + "/docs",
		"resource_policy_uri":      s.BaseURL() + "/privacy",
		"resource_tos_uri":         s.BaseURL() + "/terms",
	})
}

func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	base := s.issuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + "/oauth/authorize",
		"token_endpoint":                                 base + "/oauth/token",
		"registration_endpoint":                          base + "/oauth/register",
		"revocation_endpoint":                            base + "/oauth/revoke",
		"userinfo_endpoint":                              base + "/oauth/userinfo",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               []string{mcpScope, "openid", "email"},
		"subject_types_supported":                        []string{"public"},
		"service_documentation":                          s.BaseURL() + "/docs/connect",
		"op_policy_uri":                                  s.BaseURL() + "/privacy",
		"op_tos_uri":                                     s.BaseURL() + "/terms",
	})
}

// ---- redirect URI rules ----

func isLoopbackHost(h string) bool {
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// validRedirectURI accepts https URIs and http loopback URIs (native apps,
// RFC 8252), without fragments or credentials.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackHost(u.Hostname())
	}
	return false
}

// redirectMatches compares exactly, except that loopback redirects match
// on any port (Claude Code and other native clients bind an ephemeral port).
func redirectMatches(registered []string, given string) bool {
	gu, err := url.Parse(given)
	if err != nil {
		return false
	}
	for _, reg := range registered {
		if reg == given {
			return true
		}
		ru, err := url.Parse(reg)
		if err != nil || ru.Scheme != "http" || gu.Scheme != "http" {
			continue
		}
		if isLoopbackHost(ru.Hostname()) && isLoopbackHost(gu.Hostname()) &&
			strings.EqualFold(ru.Hostname(), gu.Hostname()) && ru.Path == gu.Path && ru.RawQuery == gu.RawQuery {
			return true
		}
	}
	return false
}

// ---- clients ----

// resolveClient loads a client by id: a Client ID Metadata Document URL is
// fetched (and cached briefly), anything else must be a registered client.
func (s *Server) resolveClient(clientID string) (store.OAuthClient, error) {
	if strings.HasPrefix(clientID, "https://") {
		cached, cerr := s.st.OAuthClientByID(clientID)
		if cerr == nil && cached.Kind == "cimd" && time.Since(time.Unix(cached.FetchedAt, 0)) < cimdFreshFor {
			return cached, nil
		}
		c, err := s.fetchClientMetadata(clientID)
		if err != nil {
			if cerr == nil && cached.Kind == "cimd" && time.Since(time.Unix(cached.FetchedAt, 0)) < cimdStaleOK {
				log.Printf("oauth: refresh %s failed (%v); using cached metadata", clientID, err)
				return cached, nil
			}
			return store.OAuthClient{}, err
		}
		if err := s.st.SaveOAuthClient(c); err != nil {
			return store.OAuthClient{}, err
		}
		return c, nil
	}
	c, err := s.st.OAuthClientByID(clientID)
	if err != nil || c.Kind != "dcr" {
		return store.OAuthClient{}, errors.New("unknown client_id")
	}
	return c, nil
}

func (s *Server) fetchClientMetadata(clientID string) (store.OAuthClient, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" || u.User != nil {
		return store.OAuthClient{}, errors.New("client_id must be an https URL with a path")
	}
	req, _ := http.NewRequest(http.MethodGet, clientID, nil)
	req.Header.Set("Accept", "application/json")
	client := s.newFetchClient()
	client.Timeout = 8 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return store.OAuthClient{}, fmt.Errorf("fetch client metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return store.OAuthClient{}, fmt.Errorf("fetch client metadata: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil || len(raw) > cimdMaxBytes {
		return store.OAuthClient{}, errors.New("client metadata document is too large")
	}
	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		ClientURI               string   `json:"client_uri"`
		LogoURI                 string   `json:"logo_uri"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return store.OAuthClient{}, errors.New("client metadata document is not valid JSON")
	}
	if doc.ClientID != clientID {
		return store.OAuthClient{}, errors.New("client metadata client_id does not match its URL")
	}
	if len(doc.RedirectURIs) == 0 {
		return store.OAuthClient{}, errors.New("client metadata has no redirect_uris")
	}
	for _, ru := range doc.RedirectURIs {
		if !validRedirectURI(ru) {
			return store.OAuthClient{}, fmt.Errorf("client metadata redirect_uri %q is not allowed", ru)
		}
	}
	if strings.HasPrefix(doc.TokenEndpointAuthMethod, "client_secret") {
		return store.OAuthClient{}, errors.New("metadata-document clients cannot use shared secrets")
	}
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		name = u.Host
	}
	return store.OAuthClient{
		ClientID: clientID, Kind: "cimd", Name: truncate(name, 80), RedirectURIs: doc.RedirectURIs,
		ClientURI: doc.ClientURI, LogoURI: doc.LogoURI, Metadata: string(raw), FetchedAt: time.Now().Unix(),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// handleRegister is RFC 7591 dynamic client registration for public clients.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.signupLimiter.allow("dcr:" + s.clientIP(r)) {
		oauthError(w, http.StatusTooManyRequests, "invalid_client_metadata", "registration rate limit; try again later")
		return
	}
	if n, err := s.st.CountDCRClientsSince(time.Now().Add(-time.Hour).Unix()); err == nil && n > 500 {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration is busy; try again shortly")
		return
	}
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		ClientURI               string   `json:"client_uri"`
		LogoURI                 string   `json:"logo_uri"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Scope                   string   `json:"scope"`
		ApplicationType         string   `json:"application_type"`
	}
	if err := decodeBody(r, &req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "provide 1-10 redirect_uris")
		return
	}
	for _, ru := range req.RedirectURIs {
		if !validRedirectURI(ru) || len(ru) > 512 {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("redirect_uri %q must be https or http loopback", ru))
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		if u, err := url.Parse(req.RedirectURIs[0]); err == nil {
			name = u.Hostname()
		}
	}
	c := store.OAuthClient{
		ClientID: "atd_" + strings.TrimPrefix(store.NewID("c"), "c_"), Kind: "dcr", Name: truncate(name, 80),
		RedirectURIs: req.RedirectURIs, ClientURI: truncate(req.ClientURI, 512), LogoURI: truncate(req.LogoURI, 512),
	}
	if err := s.st.SaveOAuthClient(c); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not register")
		return
	}
	out := map[string]any{
		"client_id":                  c.ClientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      mcpScope,
	}
	if req.ApplicationType != "" {
		out["application_type"] = req.ApplicationType
	}
	writeJSON(w, http.StatusCreated, out)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// ---- authorization endpoint ----

type authzRequest struct {
	ClientID, RedirectURI, State, Challenge, Method, Scope, Resource, ResponseType string
}

func authzFrom(v url.Values) authzRequest {
	return authzRequest{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"),
		Challenge: v.Get("code_challenge"), Method: v.Get("code_challenge_method"), Scope: v.Get("scope"),
		Resource: v.Get("resource"), ResponseType: v.Get("response_type"),
	}
}

func (a authzRequest) values() url.Values {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("client_id", a.ClientID)
	set("redirect_uri", a.RedirectURI)
	set("state", a.State)
	set("code_challenge", a.Challenge)
	set("code_challenge_method", a.Method)
	set("scope", a.Scope)
	set("resource", a.Resource)
	set("response_type", a.ResponseType)
	return v
}

// redirectWith sends the user back to the client with params plus iss (RFC 9207).
func (s *Server) redirectWith(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	q.Set("iss", s.issuer())
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// validateAuthz checks a request; a non-nil client with a matching redirect
// means later errors may be reported by redirect.
func (s *Server) validateAuthz(a authzRequest) (store.OAuthClient, bool, string, string) {
	client, err := s.resolveClient(a.ClientID)
	if err != nil {
		return client, false, "invalid_client", err.Error()
	}
	if a.RedirectURI == "" && len(client.RedirectURIs) == 1 {
		a.RedirectURI = client.RedirectURIs[0]
	}
	if !redirectMatches(client.RedirectURIs, a.RedirectURI) {
		return client, false, "invalid_request", "redirect_uri is not registered for this client"
	}
	if a.ResponseType != "code" {
		return client, true, "unsupported_response_type", "response_type must be code"
	}
	if a.Method != "S256" || len(a.Challenge) < 43 || len(a.Challenge) > 128 {
		return client, true, "invalid_request", "PKCE with code_challenge_method=S256 is required"
	}
	if !s.validResource(a.Resource) {
		return client, true, "invalid_target", "resource must be " + s.mcpResource()
	}
	return client, true, "", ""
}

func clientHost(c store.OAuthClient) string {
	if c.Kind == "cimd" {
		if u, err := url.Parse(c.ClientID); err == nil {
			return u.Hostname()
		}
	}
	for _, ru := range c.RedirectURIs {
		if u, err := url.Parse(ru); err == nil {
			return u.Hostname()
		}
	}
	return ""
}

// suggestTag names the fleet agent a client becomes (handle+chatgpt).
func suggestTag(c store.OAuthClient) string {
	host := strings.ToLower(clientHost(c))
	name := strings.ToLower(c.Name)
	switch {
	case strings.Contains(host, "chatgpt") || strings.Contains(host, "openai") || strings.Contains(name, "chatgpt"):
		return "chatgpt"
	case strings.Contains(name, "claude code"):
		return "claude-code"
	case strings.Contains(host, "claude.ai") || strings.Contains(host, "anthropic") || strings.Contains(name, "claude"):
		return "claude"
	case strings.Contains(host, "muse") || strings.Contains(name, "muse"):
		return "muse"
	case strings.Contains(host, "gemini") || strings.Contains(name, "gemini"):
		return "gemini"
	case strings.Contains(host, "perplexity") || strings.Contains(name, "perplexity"):
		return "perplexity"
	case strings.Contains(host, "x.ai") || strings.Contains(name, "grok"):
		return "grok"
	case strings.Contains(host, "cursor") || strings.Contains(name, "cursor"):
		return "cursor"
	}
	var b strings.Builder
	for _, ch := range name {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == ' ' || ch == '-' || ch == '_' || ch == '.':
			if b.Len() > 0 {
				b.WriteRune('-')
			}
		}
	}
	tag := strings.Trim(b.String(), "-")
	if len(tag) > 24 {
		tag = strings.Trim(tag[:24], "-")
	}
	if len(tag) < 3 {
		tag = "app"
	}
	return tag
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		s.renderOAuthError(w, "The authorization request was malformed.")
		return
	}
	a := authzFrom(r.Form)
	client, canRedirect, code, desc := s.validateAuthz(a)
	if a.RedirectURI == "" && len(client.RedirectURIs) == 1 {
		a.RedirectURI = client.RedirectURIs[0]
	}
	if code != "" {
		if !canRedirect {
			s.renderOAuthError(w, desc)
			return
		}
		s.redirectWith(w, r, a.RedirectURI, url.Values{"error": {code}, "error_description": {desc}, "state": {a.State}})
		return
	}
	person, sess, ok := s.currentPerson(r)
	if !ok {
		next := "/oauth/authorize?" + a.values().Encode()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		// Remembered consent: the same person already approved this exact
		// client (same client_id, so the same validated redirect set).
		if g, err := s.st.GrantFor(person.ID, client.ClientID); err == nil {
			if agent, err := s.st.AgentByID(g.AgentID); err == nil && agent.PersonID == person.ID {
				s.issueCode(w, r, a, client, person, agent)
				return
			}
		}
		s.render(w, "consent.html", map[string]any{
			"Client": client.Name, "Host": clientHost(client), "Verified": client.Kind == "cimd",
			"Tag": suggestTag(client), "Handle": person.Handle, "Domain": s.st.Instance(),
			"CSRF": sess.CSRF, "Params": a.values(),
		})
		return
	}
	// POST: the consent decision.
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
		s.renderOAuthError(w, "This consent form expired. Start connecting again from your AI app.")
		return
	}
	if r.PostFormValue("decision") != "allow" {
		s.redirectWith(w, r, a.RedirectURI, url.Values{"error": {"access_denied"}, "error_description": {"the user declined"}, "state": {a.State}})
		return
	}
	tag := strings.ToLower(strings.TrimSpace(r.PostFormValue("tag")))
	if tag == "" {
		tag = suggestTag(client)
	}
	agent, err := s.agentForGrant(person, client, tag)
	if err != nil {
		s.render(w, "consent.html", map[string]any{
			"Client": client.Name, "Host": clientHost(client), "Verified": client.Kind == "cimd",
			"Tag": tag, "Handle": person.Handle, "Domain": s.st.Instance(),
			"CSRF": sess.CSRF, "Params": a.values(), "Error": err.Error(),
		})
		return
	}
	if err := s.st.SaveGrant(store.OAuthGrant{PersonID: person.ID, ClientID: client.ClientID, AgentID: agent.ID, Scope: mcpScope}); err != nil {
		s.renderOAuthError(w, "Could not save the connection. Please try again.")
		return
	}
	s.issueCode(w, r, a, client, person, agent)
}

// agentForGrant finds or creates the fleet agent a client acts as.
func (s *Server) agentForGrant(person store.Person, client store.OAuthClient, tag string) (store.Agent, error) {
	if g, err := s.st.GrantFor(person.ID, client.ClientID); err == nil {
		if a, err := s.st.AgentByID(g.AgentID); err == nil && a.PersonID == person.ID {
			return a, nil
		}
	}
	if existing, err := s.st.AgentByName(person.Handle + "+" + tag); err == nil {
		if existing.PersonID != person.ID || existing.IsDrive() {
			return store.Agent{}, fmt.Errorf("the name %q is not available", tag)
		}
		if !existing.OwnerVerified {
			if err := s.st.MarkOwnerVerifiedBy(existing.ID, "email"); err != nil {
				return store.Agent{}, err
			}
			existing.OwnerVerified = true
		}
		return existing, nil
	}
	agent, _, err := s.st.CreateApprovedAgentForPerson(person, tag)
	if err != nil {
		return store.Agent{}, fmt.Errorf("could not create %s+%s: %v", person.Handle, tag, err)
	}
	return agent, nil
}

func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, a authzRequest, client store.OAuthClient, person store.Person, agent store.Agent) {
	resource := a.Resource
	if resource == "" {
		resource = s.mcpResource()
	}
	code, err := s.st.CreateOAuthCode(store.OAuthCode{
		ClientID: client.ClientID, PersonID: person.ID, AgentID: agent.ID, RedirectURI: a.RedirectURI,
		CodeChallenge: a.Challenge, Scope: a.Scope, Resource: resource,
	})
	if err != nil {
		s.redirectWith(w, r, a.RedirectURI, url.Values{"error": {"server_error"}, "state": {a.State}})
		return
	}
	params := url.Values{"code": {code}}
	if a.State != "" {
		params.Set("state", a.State)
	}
	s.redirectWith(w, r, a.RedirectURI, params)
}

// ---- token endpoint ----

func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "send application/x-www-form-urlencoded parameters")
		return
	}
	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		if u, _, ok := r.BasicAuth(); ok {
			clientID, _ = url.QueryUnescape(u)
		}
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		code, err := s.st.ConsumeOAuthCode(r.PostFormValue("code"))
		if errors.Is(err, store.ErrCodeReused) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code was already used; its tokens were revoked")
			return
		}
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
			return
		}
		if clientID != "" && clientID != code.ClientID {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
			return
		}
		if ru := r.PostFormValue("redirect_uri"); ru != "" && ru != code.RedirectURI {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
			return
		}
		if !pkceMatches(r.PostFormValue("code_verifier"), code.CodeChallenge) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		if res := r.PostFormValue("resource"); res != "" && !s.validResource(res) {
			oauthError(w, http.StatusBadRequest, "invalid_target", "unknown resource")
			return
		}
		access, refresh, t, err := s.st.IssueOAuthTokens(store.OAuthToken{
			Family: code.Family, ClientID: code.ClientID, PersonID: code.PersonID, AgentID: code.AgentID,
			Scope: mcpScope, Resource: code.Resource,
		}, accessTokenTTL, refreshTokenTTL)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
			return
		}
		s.tokenResponse(w, access, refresh, t)
	case "refresh_token":
		access, refresh, t, err := s.st.RotateRefreshToken(r.PostFormValue("refresh_token"), accessTokenTTL, refreshTokenTTL)
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired, or revoked")
			return
		}
		if clientID != "" && clientID != t.ClientID {
			_ = s.st.RevokeOAuthToken(refresh)
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to another client")
			return
		}
		s.tokenResponse(w, access, refresh, t)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) tokenResponse(w http.ResponseWriter, access, refresh string, t store.OAuthToken) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL / time.Second),
		"refresh_token": refresh,
		"scope":         mcpScope,
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_ = r.ParseForm()
	if tok := r.PostFormValue("token"); tok != "" {
		_ = s.st.RevokeOAuthToken(tok)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	t, err := s.st.OAuthTokenByAccess(bearer(r))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	p, err := s.st.PersonByID(t.PersonID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "account no longer exists")
		return
	}
	agent, _ := s.st.AgentByID(t.AgentID)
	writeJSON(w, http.StatusOK, map[string]any{
		"sub": p.ID, "email": p.Email, "email_verified": true,
		"preferred_username": p.Handle, "name": p.Handle, "agent": agent.Email,
	})
}

func (s *Server) renderOAuthError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "message.html", map[string]any{"Title": "Can't connect", "Message": msg})
}
