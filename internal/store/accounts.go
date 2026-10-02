package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// schemaAccountsV17 adds the human side: browser sessions, single-use sign-in
// links, optional passwords (for accounts that cannot receive mail, such as
// directory reviewers), and an OAuth 2.1 authorization server's state. Every
// secret is stored only as a sha256 hash.
//
// An OAuth grant binds (person, client) to one agent of the person's fleet —
// connecting ChatGPT creates handle+chatgpt — so tokens always act as a
// concrete, auditable agent identity, and revoking the grant disconnects it.
const schemaAccountsV17 = `
ALTER TABLE persons ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE persons ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';

CREATE TABLE web_sessions (
  id_hash TEXT PRIMARY KEY,
  person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_web_sessions_person ON web_sessions(person_id);

CREATE TABLE login_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  next TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_login_tokens_email ON login_tokens(email, created_at);

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('cimd','dcr')),
  name TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL DEFAULT '[]',
  client_uri TEXT NOT NULL DEFAULT '',
  logo_uri TEXT NOT NULL DEFAULT '',
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  fetched_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  family TEXT NOT NULL DEFAULT ''
);

CREATE TABLE oauth_tokens (
  id TEXT PRIMARY KEY,
  access_hash TEXT NOT NULL UNIQUE,
  refresh_hash TEXT NOT NULL UNIQUE,
  family TEXT NOT NULL,
  client_id TEXT NOT NULL,
  person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  scope TEXT NOT NULL DEFAULT '',
  resource TEXT NOT NULL DEFAULT '',
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  rotated INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_oauth_tokens_family ON oauth_tokens(family);
CREATE INDEX idx_oauth_tokens_agent ON oauth_tokens(agent_id);

CREATE TABLE oauth_grants (
  person_id TEXT NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  scope TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (person_id, client_id)
);
`

// ---- persons as accounts ----

// PersonByEmail resolves a person by their (case-insensitive) mailbox.
func (s *Store) PersonByEmail(email string) (Person, error) {
	return scanPerson(s.DB.QueryRow(`SELECT `+personCols+` FROM persons WHERE email=?`,
		strings.ToLower(strings.TrimSpace(email))))
}

// AvailableHandle derives a free handle from base (an email localpart or a
// requested name): lowercased, reduced to the agent-name alphabet, and
// suffixed with digits when taken.
func (s *Store) AvailableHandle(base string) (string, error) {
	base = strings.ToLower(strings.TrimSpace(base))
	var b strings.Builder
	for _, c := range base {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		case c == '.' || c == '+' || c == ' ':
			b.WriteRune('-')
		}
	}
	h := strings.Trim(b.String(), "-_")
	if len(h) > 32 {
		h = h[:32]
	}
	for len(h) < 3 {
		h += "x"
	}
	for i := 0; i < 50; i++ {
		cand := h
		if i > 0 {
			cand = fmt.Sprintf("%s%d", h, i+1)
		}
		if reservedHandle(cand) {
			continue
		}
		var n int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM local_names WHERE name=?`, cand).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("no free handle near %q: %w", h, ErrHandleTaken)
}

// reservedHandle mirrors the server's reserved localparts for persons created
// by the web sign-in flow (the API path enforces its own list).
func reservedHandle(h string) bool {
	switch h {
	case "abuse", "admin", "administrator", "agenttransfer", "help", "hostmaster", "info",
		"mail", "mailer-daemon", "no-reply", "noreply", "postmaster", "root", "security",
		"self", "support", "system", "upload-request", "webmaster", "www", "concierge",
		"hello", "team", "billing", "privacy", "legal", "api", "oauth", "login", "account":
		return true
	}
	return false
}

// CreateVerifiedPerson creates an account for a mailbox that has just proven
// control (a consumed sign-in link). The handle is chosen with AvailableHandle.
func (s *Store) CreateVerifiedPerson(email, handleBase string) (Person, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return Person{}, errors.New("a person needs an email")
	}
	if handleBase == "" {
		handleBase, _, _ = strings.Cut(email, "@")
	}
	for attempt := 0; attempt < 3; attempt++ {
		handle, err := s.AvailableHandle(handleBase)
		if err != nil {
			return Person{}, err
		}
		p := Person{ID: NewID("prs"), Handle: handle, Email: email, VerifiedAt: now(), CreatedAt: now()}
		_, err = s.DB.Exec(`INSERT INTO persons(id,handle,email,verified_at,created_at) VALUES(?,?,?,?,?)`,
			p.ID, p.Handle, p.Email, p.VerifiedAt, p.CreatedAt)
		if err == nil {
			return p, nil
		}
		if !strings.Contains(err.Error(), "UNIQUE") {
			return Person{}, err
		}
		if existing, perr := s.PersonByEmail(email); perr == nil {
			return existing, nil // the mailbox raced us into an account
		}
	}
	return Person{}, fmt.Errorf("could not allocate a handle: %w", ErrHandleTaken)
}

// RenamePerson changes a verified person's handle while no agents exist yet
// beyond the drive — the first-run "pick your handle" step. Agent names embed
// the handle, so renames after agents exist are refused.
func (s *Store) RenamePerson(personID, handle string) error {
	handle = strings.ToLower(strings.TrimSpace(handle))
	if !ValidAgentName(handle) || strings.Contains(handle, "+") || reservedHandle(handle) {
		return errors.New("invalid handle: use 3-64 chars of a-z 0-9 . _ -")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM agents WHERE person_id=?`, personID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("handle can't change once agents are connected")
	}
	if _, err := tx.Exec(`UPDATE persons SET handle=? WHERE id=?`, handle, personID); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("handle %q is taken: %w", handle, ErrHandleTaken)
		}
		return err
	}
	return tx.Commit()
}

// argon2id parameters (OWASP baseline: 19 MiB, t=2, p=1).
const (
	pwTime    = 2
	pwMemory  = 19 * 1024
	pwThreads = 1
	pwKeyLen  = 32
)

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, pwTime, pwMemory, pwThreads, pwKeyLen)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s", pwTime, pwMemory, pwThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword verifies pw against an encoded argon2id hash in constant time.
func CheckPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}
	var t, m uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[1]+" "+parts[2]+" "+parts[3], "%d %d %d", &t, &m, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || t == 0 || m == 0 || p == 0 || m > 256*1024 || t > 10 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// SetPassword stores (or clears, with "") a person's password hash.
func (s *Store) SetPassword(personID, encodedHash string) error {
	_, err := s.DB.Exec(`UPDATE persons SET password_hash=? WHERE id=?`, encodedHash, personID)
	return err
}

// PasswordHash returns a person's encoded hash ("" when none is set).
func (s *Store) PasswordHash(personID string) (string, error) {
	var h string
	err := s.DB.QueryRow(`SELECT password_hash FROM persons WHERE id=?`, personID).Scan(&h)
	return h, errNoRows(err)
}

// PersonPlan returns the person's plan ("free" by default).
func (s *Store) PersonPlan(personID string) string {
	var plan string
	if err := s.DB.QueryRow(`SELECT plan FROM persons WHERE id=?`, personID).Scan(&plan); err != nil || plan == "" {
		return "free"
	}
	return plan
}

// SetPersonPlan sets a person's plan (operator action).
func (s *Store) SetPersonPlan(personID, plan string) error {
	res, err := s.DB.Exec(`UPDATE persons SET plan=? WHERE id=?`, plan, personID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- web sessions ----

// WebSession is a signed-in browser.
type WebSession struct {
	PersonID  string
	CSRF      string
	ExpiresAt int64
}

// CreateWebSession mints a session token (returned once) bound to personID.
func (s *Store) CreateWebSession(personID string, ttl time.Duration) (string, WebSession, error) {
	tok := "ats_" + randToken(32)
	ws := WebSession{PersonID: personID, CSRF: randToken(24), ExpiresAt: time.Now().Add(ttl).Unix()}
	_, err := s.DB.Exec(`INSERT INTO web_sessions(id_hash,person_id,csrf,created_at,expires_at) VALUES(?,?,?,?,?)`,
		hashToken(tok), personID, ws.CSRF, now(), ws.ExpiresAt)
	return tok, ws, err
}

// LookupWebSession resolves a live session token.
func (s *Store) LookupWebSession(tok string) (WebSession, error) {
	if tok == "" {
		return WebSession{}, ErrNotFound
	}
	var ws WebSession
	err := s.DB.QueryRow(`SELECT person_id,csrf,expires_at FROM web_sessions WHERE id_hash=? AND expires_at>?`,
		hashToken(tok), now()).Scan(&ws.PersonID, &ws.CSRF, &ws.ExpiresAt)
	return ws, errNoRows(err)
}

// DeleteWebSession signs one browser out.
func (s *Store) DeleteWebSession(tok string) error {
	_, err := s.DB.Exec(`DELETE FROM web_sessions WHERE id_hash=?`, hashToken(tok))
	return err
}

// ---- sign-in links ----

// CountRecentLoginTokens counts links minted for email since a cutoff (rate limiting).
func (s *Store) CountRecentLoginTokens(email string, since int64) (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM login_tokens WHERE email=? AND created_at>=?`,
		strings.ToLower(strings.TrimSpace(email)), since).Scan(&n)
	return n, err
}

// CreateLoginToken mints a single-use sign-in link token for email.
func (s *Store) CreateLoginToken(email, next string, ttl time.Duration) (string, error) {
	tok := "atl_" + randToken(32)
	_, err := s.DB.Exec(`INSERT INTO login_tokens(token_hash,email,next,created_at,expires_at) VALUES(?,?,?,?,?)`,
		hashToken(tok), strings.ToLower(strings.TrimSpace(email)), next, now(), time.Now().Add(ttl).Unix())
	return tok, err
}

// PeekLoginToken returns a live token's email without consuming it (the GET
// confirm page must not sign in: mail scanners prefetch links).
func (s *Store) PeekLoginToken(tok string) (email, next string, err error) {
	err = s.DB.QueryRow(`SELECT email,next FROM login_tokens WHERE token_hash=? AND used=0 AND expires_at>?`,
		hashToken(tok), now()).Scan(&email, &next)
	return email, next, errNoRows(err)
}

// ConsumeLoginToken marks a live token used and returns its email.
func (s *Store) ConsumeLoginToken(tok string) (email, next string, err error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(`SELECT email,next FROM login_tokens WHERE token_hash=? AND used=0 AND expires_at>?`,
		hashToken(tok), now()).Scan(&email, &next); err != nil {
		return "", "", errNoRows(err)
	}
	if _, err := tx.Exec(`UPDATE login_tokens SET used=1 WHERE token_hash=?`, hashToken(tok)); err != nil {
		return "", "", err
	}
	return email, next, tx.Commit()
}

// ---- OAuth clients ----

// OAuthClient is a registered (DCR) or metadata-document (CIMD) client.
type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	Kind         string   `json:"kind"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientURI    string   `json:"client_uri,omitempty"`
	LogoURI      string   `json:"logo_uri,omitempty"`
	Metadata     string   `json:"-"`
	CreatedAt    int64    `json:"-"`
	FetchedAt    int64    `json:"-"`
}

// SaveOAuthClient inserts or refreshes a client record.
func (s *Store) SaveOAuthClient(c OAuthClient) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	if c.Metadata == "" {
		c.Metadata = "{}"
	}
	_, err := s.DB.Exec(`INSERT INTO oauth_clients(client_id,kind,name,redirect_uris,client_uri,logo_uri,metadata,created_at,fetched_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(client_id) DO UPDATE SET name=excluded.name, redirect_uris=excluded.redirect_uris,
			client_uri=excluded.client_uri, logo_uri=excluded.logo_uri, metadata=excluded.metadata,
			fetched_at=excluded.fetched_at`,
		c.ClientID, c.Kind, c.Name, string(uris), c.ClientURI, c.LogoURI, c.Metadata, now(), c.FetchedAt)
	return err
}

// OAuthClientByID loads a client.
func (s *Store) OAuthClientByID(id string) (OAuthClient, error) {
	var c OAuthClient
	var uris string
	err := s.DB.QueryRow(`SELECT client_id,kind,name,redirect_uris,client_uri,logo_uri,metadata,created_at,fetched_at
		FROM oauth_clients WHERE client_id=?`, id).Scan(&c.ClientID, &c.Kind, &c.Name, &uris,
		&c.ClientURI, &c.LogoURI, &c.Metadata, &c.CreatedAt, &c.FetchedAt)
	if err != nil {
		return c, errNoRows(err)
	}
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	return c, nil
}

// CountDCRClientsSince bounds dynamic registration volume.
func (s *Store) CountDCRClientsSince(since int64) (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM oauth_clients WHERE kind='dcr' AND created_at>=?`, since).Scan(&n)
	return n, err
}

// ---- OAuth codes ----

// OAuthCode is an issued authorization code.
type OAuthCode struct {
	ClientID      string
	PersonID      string
	AgentID       string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	Family        string
}

// CreateOAuthCode mints a 60-second, single-use authorization code.
func (s *Store) CreateOAuthCode(c OAuthCode) (string, error) {
	code := "atc_" + randToken(32)
	if c.Family == "" {
		c.Family = NewID("fam")
	}
	_, err := s.DB.Exec(`INSERT INTO oauth_codes(code_hash,client_id,person_id,agent_id,redirect_uri,code_challenge,
		scope,resource,created_at,expires_at,family) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		hashToken(code), c.ClientID, c.PersonID, c.AgentID, c.RedirectURI, c.CodeChallenge,
		c.Scope, c.Resource, now(), now()+60, c.Family)
	return code, err
}

// ErrCodeReused reports a replayed authorization code; the caller must treat
// every token minted from it as compromised (RFC 9700 §4.4).
var ErrCodeReused = errors.New("authorization code already used")

// ConsumeOAuthCode redeems a code exactly once. A second redemption revokes
// the token family the first one produced.
func (s *Store) ConsumeOAuthCode(code string) (OAuthCode, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return OAuthCode{}, err
	}
	defer tx.Rollback()
	var c OAuthCode
	var used int
	var expires int64
	err = tx.QueryRow(`SELECT client_id,person_id,agent_id,redirect_uri,code_challenge,scope,resource,family,used,expires_at
		FROM oauth_codes WHERE code_hash=?`, hashToken(code)).Scan(&c.ClientID, &c.PersonID, &c.AgentID,
		&c.RedirectURI, &c.CodeChallenge, &c.Scope, &c.Resource, &c.Family, &used, &expires)
	if err != nil {
		return OAuthCode{}, errNoRows(err)
	}
	if used == 1 {
		_, _ = tx.Exec(`UPDATE oauth_tokens SET revoked=1 WHERE family=?`, c.Family)
		_ = tx.Commit()
		return OAuthCode{}, ErrCodeReused
	}
	if expires <= now() {
		return OAuthCode{}, ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE oauth_codes SET used=1 WHERE code_hash=?`, hashToken(code)); err != nil {
		return OAuthCode{}, err
	}
	return c, tx.Commit()
}

// ---- OAuth tokens ----

// OAuthToken is a live access/refresh pair.
type OAuthToken struct {
	ID               string
	Family           string
	ClientID         string
	PersonID         string
	AgentID          string
	Scope            string
	Resource         string
	AccessExpiresAt  int64
	RefreshExpiresAt int64
}

// IssueOAuthTokens mints an access token and a refresh token in family.
func (s *Store) IssueOAuthTokens(t OAuthToken, accessTTL, refreshTTL time.Duration) (access, refresh string, out OAuthToken, err error) {
	access = "at_oat_" + randToken(32)
	refresh = "at_ort_" + randToken(32)
	t.ID = NewID("tok")
	t.AccessExpiresAt = time.Now().Add(accessTTL).Unix()
	t.RefreshExpiresAt = time.Now().Add(refreshTTL).Unix()
	_, err = s.DB.Exec(`INSERT INTO oauth_tokens(id,access_hash,refresh_hash,family,client_id,person_id,agent_id,scope,resource,
		access_expires_at,refresh_expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, hashToken(access), hashToken(refresh), t.Family, t.ClientID, t.PersonID, t.AgentID, t.Scope, t.Resource,
		t.AccessExpiresAt, t.RefreshExpiresAt, now())
	return access, refresh, t, err
}

const oauthTokenCols = `id,family,client_id,person_id,agent_id,scope,resource,access_expires_at,refresh_expires_at`

func scanOAuthToken(row interface{ Scan(...any) error }) (OAuthToken, error) {
	var t OAuthToken
	err := row.Scan(&t.ID, &t.Family, &t.ClientID, &t.PersonID, &t.AgentID, &t.Scope, &t.Resource,
		&t.AccessExpiresAt, &t.RefreshExpiresAt)
	return t, errNoRows(err)
}

// OAuthTokenByAccess resolves a live access token.
func (s *Store) OAuthTokenByAccess(access string) (OAuthToken, error) {
	return scanOAuthToken(s.DB.QueryRow(`SELECT `+oauthTokenCols+` FROM oauth_tokens
		WHERE access_hash=? AND revoked=0 AND access_expires_at>?`, hashToken(access), now()))
}

// ErrRefreshReused reports a rotated refresh token being replayed; the whole
// family has been revoked.
var ErrRefreshReused = errors.New("refresh token reused")

// RotateRefreshToken exchanges a live refresh token for a new pair in the
// same family. Presenting an already-rotated token revokes the family.
func (s *Store) RotateRefreshToken(refresh string, accessTTL, refreshTTL time.Duration) (string, string, OAuthToken, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", "", OAuthToken{}, err
	}
	defer tx.Rollback()
	var t OAuthToken
	var rotated, revoked int
	err = tx.QueryRow(`SELECT `+oauthTokenCols+`,rotated,revoked FROM oauth_tokens WHERE refresh_hash=?`,
		hashToken(refresh)).Scan(&t.ID, &t.Family, &t.ClientID, &t.PersonID, &t.AgentID, &t.Scope, &t.Resource,
		&t.AccessExpiresAt, &t.RefreshExpiresAt, &rotated, &revoked)
	if err != nil {
		return "", "", OAuthToken{}, errNoRows(err)
	}
	if rotated == 1 {
		_, _ = tx.Exec(`UPDATE oauth_tokens SET revoked=1 WHERE family=?`, t.Family)
		_ = tx.Commit()
		return "", "", OAuthToken{}, ErrRefreshReused
	}
	if revoked == 1 || t.RefreshExpiresAt <= now() {
		return "", "", OAuthToken{}, ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE oauth_tokens SET rotated=1, access_expires_at=MIN(access_expires_at,?) WHERE id=?`,
		now(), t.ID); err != nil {
		return "", "", OAuthToken{}, err
	}
	access := "at_oat_" + randToken(32)
	newRefresh := "at_ort_" + randToken(32)
	nt := t
	nt.ID = NewID("tok")
	nt.AccessExpiresAt = time.Now().Add(accessTTL).Unix()
	nt.RefreshExpiresAt = time.Now().Add(refreshTTL).Unix()
	if _, err := tx.Exec(`INSERT INTO oauth_tokens(id,access_hash,refresh_hash,family,client_id,person_id,agent_id,scope,resource,
		access_expires_at,refresh_expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		nt.ID, hashToken(access), hashToken(newRefresh), nt.Family, nt.ClientID, nt.PersonID, nt.AgentID, nt.Scope,
		nt.Resource, nt.AccessExpiresAt, nt.RefreshExpiresAt, now()); err != nil {
		return "", "", OAuthToken{}, err
	}
	return access, newRefresh, nt, tx.Commit()
}

// RevokeOAuthToken revokes the family of whichever token (access or refresh)
// matches. Unknown tokens succeed silently (RFC 7009).
func (s *Store) RevokeOAuthToken(tok string) error {
	h := hashToken(tok)
	_, err := s.DB.Exec(`UPDATE oauth_tokens SET revoked=1 WHERE family IN
		(SELECT family FROM oauth_tokens WHERE access_hash=? OR refresh_hash=?)`, h, h)
	return err
}

// RevokeAgentTokens revokes every OAuth token acting as agentID.
func (s *Store) RevokeAgentTokens(agentID string) error {
	_, err := s.DB.Exec(`UPDATE oauth_tokens SET revoked=1 WHERE agent_id=?`, agentID)
	return err
}

// ---- OAuth grants ----

// OAuthGrant binds a person's consent for a client to one fleet agent.
type OAuthGrant struct {
	PersonID   string
	ClientID   string
	AgentID    string
	Scope      string
	CreatedAt  int64
	LastUsedAt int64
}

// GrantFor returns the existing grant, if any.
func (s *Store) GrantFor(personID, clientID string) (OAuthGrant, error) {
	var g OAuthGrant
	err := s.DB.QueryRow(`SELECT person_id,client_id,agent_id,scope,created_at,last_used_at FROM oauth_grants
		WHERE person_id=? AND client_id=?`, personID, clientID).Scan(&g.PersonID, &g.ClientID, &g.AgentID,
		&g.Scope, &g.CreatedAt, &g.LastUsedAt)
	return g, errNoRows(err)
}

// SaveGrant records (or re-points) a person's grant for a client.
func (s *Store) SaveGrant(g OAuthGrant) error {
	_, err := s.DB.Exec(`INSERT INTO oauth_grants(person_id,client_id,agent_id,scope,created_at) VALUES(?,?,?,?,?)
		ON CONFLICT(person_id,client_id) DO UPDATE SET agent_id=excluded.agent_id, scope=excluded.scope`,
		g.PersonID, g.ClientID, g.AgentID, g.Scope, now())
	return err
}

// TouchGrant records use of a grant (for the "last used" column).
func (s *Store) TouchGrant(agentID string) {
	_, _ = s.DB.Exec(`UPDATE oauth_grants SET last_used_at=? WHERE agent_id=? AND last_used_at<?`, now(), agentID, now()-60)
}

// GrantsByPerson lists a person's connected OAuth clients.
func (s *Store) GrantsByPerson(personID string) ([]OAuthGrant, error) {
	rows, err := s.DB.Query(`SELECT person_id,client_id,agent_id,scope,created_at,last_used_at FROM oauth_grants
		WHERE person_id=? ORDER BY created_at`, personID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuthGrant
	for rows.Next() {
		var g OAuthGrant
		if err := rows.Scan(&g.PersonID, &g.ClientID, &g.AgentID, &g.Scope, &g.CreatedAt, &g.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateApprovedAgentForPerson adds an agent to a verified person's fleet,
// approved immediately: the caller holds proof the person is present (a
// signed-in browser session or an OAuth consent). It returns the agent and
// its API key; OAuth callers simply never reveal the key.
func (s *Store) CreateApprovedAgentForPerson(p Person, tag string) (Agent, string, error) {
	if !p.Verified() {
		return Agent{}, "", errors.New("person is not verified")
	}
	a, key, err := s.CreateAgentForPersonLimited(p, tag, 0)
	if err != nil {
		return Agent{}, "", err
	}
	if err := s.MarkOwnerVerifiedBy(a.ID, "email"); err != nil {
		return Agent{}, "", err
	}
	a, err = s.AgentByID(a.ID)
	return a, key, err
}

// PruneAccounts drops expired sessions, links, codes and long-dead tokens.
func (s *Store) PruneAccounts() error {
	for _, q := range []string{
		`DELETE FROM web_sessions WHERE expires_at<?`,
		`DELETE FROM login_tokens WHERE expires_at<?`,
		`DELETE FROM oauth_codes WHERE expires_at<?`,
	} {
		if _, err := s.DB.Exec(q, now()-3600); err != nil {
			return err
		}
	}
	_, err := s.DB.Exec(`DELETE FROM oauth_tokens WHERE refresh_expires_at<? OR (revoked=1 AND created_at<?)`,
		now()-24*3600, now()-30*24*3600)
	return err
}
