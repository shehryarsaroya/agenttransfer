// Package store is AgentTransfer's persistence layer: one SQLite database plus
// a sha256-addressed blob directory. Database references are evaluated by the
// orphan collector; there is no mutable blob refcount. The package also owns
// the instance ed25519 identity and writes the signed receipt chain.
package store

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrQuota is returned when an upload would exceed the agent's storage quota
// or the max file size.
var ErrQuota = errors.New("storage quota exceeded")

// ErrDiskReserve is returned when continuing a blob stream would cross the
// operator's free-space floor.
var ErrDiskReserve = errors.New("disk reserve reached")

// ErrCircleFull is returned when a send would add more unique remote
// recipients than the agent's circle allows.
var ErrCircleFull = errors.New("recipient circle full")

// ErrNameTaken is returned when an agent name is already registered.
var ErrNameTaken = errors.New("name taken")

// ErrLimit is returned when a finite durable-metadata or inbox ceiling is hit.
var ErrLimit = errors.New("resource limit reached")

// ErrInboxFull distinguishes a recipient mailbox ceiling from other store
// failures so SMTP can return a retryable mailbox-full response.
var ErrInboxFull = errors.New("inbox storage limit reached")

// ErrIdempotencyConflict means a key was already bound to a different request.
var ErrIdempotencyConflict = errors.New("idempotency key request conflict")

// ErrOwnerAgentLimit means a mailbox has no remaining human-verified agent
// slots. Pending, unproven nominations never contribute to this limit.
var ErrOwnerAgentLimit = errors.New("verified owner agent limit reached")

const (
	MaxActiveLinksPerAgent     = 1000
	MaxUploadRequestsPerAgent  = 100
	MaxInboxMessagesPerAgent   = 5000
	MaxInboxBytesPerAgent      = 256 << 20
	DefaultInboxListLimit      = 100
	MaxInboxListLimit          = 500
	MaxIdempotencyKeyBytes     = 128
	MaxIdempotencyRowsPerAgent = 256
	IdempotencyTTLSeconds      = 24 * 60 * 60
)

// Agent is one identity: an email address plus an API key.
type Agent struct {
	ID                      string `json:"agent_id"`
	Name                    string `json:"name"`
	Email                   string `json:"email"`
	OwnerEmail              string `json:"owner_email,omitempty"`
	OwnerVerified           bool   `json:"owner_verified"`
	OwnerVerifiedAt         int64  `json:"owner_verified_at,omitempty"`
	OwnerVerificationMethod string `json:"owner_verification_method,omitempty"`
	AlwaysCCOwner           bool   `json:"always_cc_owner"`
	// Pubkey is the agent's published X25519 recipient ("age1...") for sealed
	// transfers, or "" if it hasn't set one. Senders fetch it to encrypt so
	// only this agent can decrypt; the private half never reaches the server.
	Pubkey string `json:"pubkey,omitempty"`
	// AcceptPolicy governs who reaches this agent's main inbox vs quarantine:
	// "open" (all), "known" (allowlisted or a space co-member; others quarantine),
	// "closed" (known only; others rejected).
	AcceptPolicy string `json:"accept_policy,omitempty"`
	// PublicContact is an address/URL/handle the agent opted to publish. Its
	// private owner_email is never exposed; this is the selectively-disclosed one.
	PublicContact string `json:"public_contact,omitempty"`
	// HumanRecipientsMax overrides the instance-wide cap on unique remote
	// recipients for this agent: 0 = instance default, <0 = unlimited.
	HumanRecipientsMax int64 `json:"-"`
	// PersonID links a person-owned agent (name = handle+tag) to its person;
	// "" for flat-named keyed agents.
	PersonID  string `json:"person_id,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// AttachPending reports a person-owned agent whose join click hasn't happened.
// Pending agents authenticate and work (scratchpad tier) but are unreachable —
// no person fan-out, no plus-address delivery, no pubkey lookup — so a
// squatter's dana+evil can never intercept mail meant for Dana's fleet.
func (a Agent) AttachPending() bool { return a.PersonID != "" && !a.OwnerVerified }

// HumanVerified reports whether a human mailbox, rather than merely the
// instance operator, vouched for this agent. Hosting uses this stronger gate:
// an admin-created ownerless agent may be trusted by the operator, but it has
// not proved control of a human email address.
func (a Agent) HumanVerified() bool {
	if strings.TrimSpace(a.OwnerEmail) == "" || !a.OwnerVerified {
		return false
	}
	// Historical rows cannot distinguish an old admin approval from a real
	// mailbox click. They retain the legacy mail/storage tier, but hosting is
	// fail-closed until a fresh email challenge records "email".
	return a.OwnerVerificationMethod == "email"
}

// File is one entry in an agent's folder. Claimed means the agent owns it
// (its own upload, or an arrival it kept); unclaimed files (inbound
// attachments, upload-request drops) await a keep. ExpiresAt > 0 makes a
// file mortal regardless of claiming — the unverified-owner tier uploads
// with an expiry that verification later lifts.
type File struct {
	ID        string `json:"id"`
	AgentID   string `json:"-"`
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	MIME      string `json:"mime"`
	Size      int64  `json:"size"`
	Source    string `json:"source"` // upload | inbound | request
	Claimed   bool   `json:"claimed"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // unix; 0 = never
	CreatedAt int64  `json:"created_at"`
}

// Link is an ephemeral, unguessable share link over a blob.
type Link struct {
	Token     string `json:"token"`
	AgentID   string `json:"-"`
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	MIME      string `json:"mime"`
	Size      int64  `json:"size"`
	Once      bool   `json:"once"`
	Downloads int64  `json:"downloads"`
	Status    string `json:"status"` // active | revoked | burned | expired
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

// Attachment describes an inbound email attachment ingested into the folder.
type Attachment struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	MIME   string `json:"mime"`
	Size   int64  `json:"size"`
}

// Message is one inbox entry.
type Message struct {
	ID          string       `json:"id"`
	AgentID     string       `json:"-"`
	From        string       `json:"from"`
	To          []string     `json:"to"`
	Subject     string       `json:"subject"`
	Text        string       `json:"text"`
	MessageID   string       `json:"message_id"`
	InReplyTo   string       `json:"in_reply_to,omitempty"`
	References  string       `json:"references,omitempty"`
	Manifest    string       `json:"-"` // raw manifest JSON, if any
	Attachments []Attachment `json:"attachments"`
	DKIM        string       `json:"dkim"`
	SPF         string       `json:"spf"`
	Read        bool         `json:"read"`
	// Quarantined marks a message held out of the main inbox by the recipient's
	// accept policy (unknown sender). It's still readable via ?quarantined=1.
	Quarantined bool  `json:"quarantined,omitempty"`
	ReceivedAt  int64 `json:"received_at"`
}

// UploadRequest is a one-time browser upload page handed to a human.
type UploadRequest struct {
	Token     string
	AgentID   string
	Note      string
	Used      bool
	ExpiresAt int64
	CreatedAt int64
}

// Store wraps the database, blob directory, and instance identity.
type Store struct {
	DB      *sql.DB
	dataDir string

	instanceMu sync.RWMutex
	instance   string // domain used in receipts and addresses

	signKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey

	adminHash string // sha256 hex of the admin token

	// diskReserve is the free-space floor (bytes) on the data-dir volume;
	// uploads are refused while free space is below it. 0 = guard disabled.
	diskReserve int64
	// diskWriteMu protects per-chunk admission. diskPending reserves bytes for
	// writes admitted after statfs but not yet reflected in filesystem free space,
	// so concurrent streams cannot spend the same headroom.
	diskWriteMu sync.Mutex
	diskPending int64
	volumeStats func(string) (int64, int64, error)

	chainMu sync.Mutex // serializes receipt appends

	// blobMu serializes blob finalization (row write + byte write) against
	// the orphan GC (row delete + unlink) — see PutBlob and DeleteOrphanBlobs.
	blobMu sync.Mutex
}

// Open opens (creating if needed) the store at dataDir. adminToken, if
// non-empty, becomes the admin token; otherwise one is generated on first
// boot and returned in firstBootAdminToken exactly once.
func Open(dataDir, adminToken string) (s *Store, firstBootAdminToken string, err error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "blobs"), 0o700); err != nil {
		return nil, "", err
	}
	dsn := "file:" + filepath.Join(dataDir, "agenttransfer.db") +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, "", err
	}
	// modernc.org/sqlite serializes writes; a single connection avoids
	// SQLITE_BUSY between our own writers.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, "", fmt.Errorf("migrate: %w", err)
	}

	s = &Store{DB: db, dataDir: dataDir, instance: "local", volumeStats: VolumeStats}

	// Instance signing key.
	seedHex, err := s.getSetting("sign_seed")
	if err != nil {
		return nil, "", err
	}
	if seedHex == "" {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, "", err
		}
		seedHex = hex.EncodeToString(seed)
		if err := s.setSetting("sign_seed", seedHex); err != nil {
			return nil, "", err
		}
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, "", errors.New("corrupt sign_seed setting")
	}
	s.signKey = ed25519.NewKeyFromSeed(seed)
	s.pubKey = s.signKey.Public().(ed25519.PublicKey)

	// Admin token.
	if adminToken != "" {
		s.adminHash = hashToken(adminToken)
		if err := s.setSetting("admin_hash", s.adminHash); err != nil {
			return nil, "", err
		}
	} else {
		s.adminHash, err = s.getSetting("admin_hash")
		if err != nil {
			return nil, "", err
		}
		if s.adminHash == "" {
			firstBootAdminToken = "at_admin_" + randToken(32)
			s.adminHash = hashToken(firstBootAdminToken)
			if err := s.setSetting("admin_hash", s.adminHash); err != nil {
				return nil, "", err
			}
		}
	}
	return s, firstBootAdminToken, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// SetInstance sets the domain recorded on receipts and used in addresses.
func (s *Store) SetInstance(domain string) {
	if domain == "" {
		return
	}
	s.instanceMu.Lock()
	s.instance = domain
	s.instanceMu.Unlock()
}

// Instance returns the instance domain ("local" when unconfigured).
func (s *Store) Instance() string {
	s.instanceMu.RLock()
	defer s.instanceMu.RUnlock()
	return s.instance
}

// PublicKey returns the instance receipt-signing public key.
func (s *Store) PublicKey() ed25519.PublicKey { return s.pubKey }

// IsAdmin reports whether tok is the admin token.
func (s *Store) IsAdmin(tok string) bool {
	if tok == "" || s.adminHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(tok)), []byte(s.adminHash)) == 1
}

// schemaBase is migration 1: the base tables. Agent-scoped children carry
// ON DELETE CASCADE so DeleteAgent only removes the parent row. Blobs have no
// refcount column — orphans are computed on demand by DeleteOrphanBlobs.
const schemaBase = `
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  owner_email TEXT NOT NULL DEFAULT '',
  owner_verified INTEGER NOT NULL DEFAULT 0,
  always_cc_owner INTEGER NOT NULL DEFAULT 0,
  human_recipients_max INTEGER NOT NULL DEFAULT 0,
  pubkey TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_key ON agents(key_hash);

CREATE TABLE IF NOT EXISTS human_recipients (
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  addr TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, addr)
);

CREATE TABLE IF NOT EXISTS suppressed (
  addr TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
  sha256 TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  name TEXT NOT NULL,
  mime TEXT NOT NULL DEFAULT 'application/octet-stream',
  size INTEGER NOT NULL,
  source TEXT NOT NULL DEFAULT 'upload',
  claimed INTEGER NOT NULL DEFAULT 1,
  expires_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  UNIQUE(agent_id, name, sha256)
);
CREATE INDEX IF NOT EXISTS idx_files_agent ON files(agent_id);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_expiry ON files(expires_at) WHERE expires_at > 0;

CREATE TABLE IF NOT EXISTS links (
  token TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  once INTEGER NOT NULL DEFAULT 0,
  downloads INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_links_agent ON links(agent_id);
CREATE INDEX IF NOT EXISTS idx_links_sha ON links(sha256) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_links_expiry ON links(expires_at);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  from_addr TEXT NOT NULL,
  to_addrs TEXT NOT NULL DEFAULT '[]',
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  message_id TEXT NOT NULL DEFAULT '',
  in_reply_to TEXT NOT NULL DEFAULT '',
  refs TEXT NOT NULL DEFAULT '',
  manifest TEXT NOT NULL DEFAULT '',
  attachments TEXT NOT NULL DEFAULT '[]',
  dkim TEXT NOT NULL DEFAULT 'none',
  spf TEXT NOT NULL DEFAULT 'none',
  read INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_agent ON messages(agent_id, received_at);

CREATE TABLE IF NOT EXISTS receipts (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL,
  instance TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  sha256 TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL DEFAULT 0,
  target TEXT NOT NULL DEFAULT '',
  message_id TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL,
  sig TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_actor ON receipts(actor, seq);

CREATE TABLE IF NOT EXISTS idempotency (
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  response TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, key)
);

CREATE TABLE IF NOT EXISTS verify_tokens (
  token TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS upload_requests (
  token TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  note TEXT NOT NULL DEFAULT '',
  used INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (
  agent_id TEXT NOT NULL,
  day TEXT NOT NULL,
  kind TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (agent_id, day, kind)
);
`

// schemaOwnerPendingV13 timestamps the current unverified mailbox nomination.
// Agent created_at is insufficient because an old ownerless agent can nominate
// a mailbox years later and must still receive a fresh 48-hour challenge window.
const schemaOwnerPendingV13 = `
ALTER TABLE agents ADD COLUMN owner_pending_at INTEGER NOT NULL DEFAULT 0;
UPDATE agents SET owner_pending_at=created_at
WHERE owner_email<>'' AND owner_verified=0;
`

// migrations is the ordered list of schema versions. Each entry is applied once,
// in order, inside a transaction; PRAGMA user_version records how many have run.
// Append new migrations — never edit a shipped one. Index i is "version i+1".
var migrations = []string{
	schemaBase + schemaConnect + schemaWebhooks, // v1
	schemaCards,                 // v2: opt-in discovery cards + directory
	schemaSpaces,                // v3: spaces
	schemaPolicy,                // v4: recipient accept policy + quarantine
	schemaIdentityV5,            // v5: opt-in public_contact for the visible identity layer
	schemaPersonsV6,             // v6: persons + plus-addressed agents (handle+tag@instance)
	schemaOwnerVerificationV7,   // v7: verification provenance (human email vs operator)
	schemaAppsV8,                // v8: per-agent app identity + immutable deployments
	schemaAppContainerHistoryV9, // v9: retain runner-data history across metadata reset
	schemaVerifyTokenOwnerV10,   // v10: bind owner challenges to the nominated mailbox
	schemaLocalNamesV11,         // v11: atomic shared person/agent localpart namespace
	schemaIdempotencyV12,        // v12: request-bound status/body idempotency records
	schemaOwnerPendingV13,       // v13: age unverified mailbox nominations independently
}

// migrate brings db up to len(migrations) via PRAGMA user_version.
func migrate(db *sql.DB) error {
	var ver int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	for i := ver; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// PRAGMA can't bind params; the value is a trusted loop int.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- settings ----

func (s *Store) getSetting(k string) (string, error) {
	var v string
	err := s.DB.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) setSetting(k, v string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// ---- ids & tokens ----

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a prefixed, unguessable identifier like "msg_ab3k...".
func NewID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + strings.ToLower(b32.EncodeToString(b))
}

// NewLinkToken returns a 128-bit share-link token.
func NewLinkToken() string { return randToken(16) }

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func now() int64 { return time.Now().Unix() }

// ---- agents ----

// CreateAgent mints an agent and returns it with the plaintext API key
// (stored only as a hash).
func (s *Store) CreateAgent(name, ownerEmail string, verified bool) (Agent, string, error) {
	return s.CreateAgentLimited(name, ownerEmail, verified, 0)
}

// CreateAgentLimited mints a flat agent. maxAgents is retained in the internal
// signature for callers compiled against the earlier flow but intentionally is
// not enforced here: merely typing a victim's mailbox proves nothing and must
// not consume that mailbox's verified-agent slots. The cap is claimed only by
// VerifyOwnerTokenLimited after mailbox proof.
func (s *Store) CreateAgentLimited(name, ownerEmail string, verified bool, _ int64) (Agent, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	ownerEmail = strings.TrimSpace(ownerEmail)
	if !ValidAgentName(name) || strings.Contains(name, "+") {
		return Agent{}, "", errors.New("invalid agent name: use 3-64 chars of a-z 0-9 . _ - (person-owned agents are created via \"as\")")
	}
	// Hold the domain snapshot through the insert. RenameInstance takes the
	// write side across its bulk UPDATE, so a concurrent registration either
	// updates this new row or this creation observes the new domain.
	s.instanceMu.RLock()
	defer s.instanceMu.RUnlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return Agent{}, "", err
	}
	defer tx.Rollback()
	// Flat names share the localpart namespace with person handles.
	var handleN int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM persons WHERE handle=?`, name).Scan(&handleN); err != nil {
		return Agent{}, "", err
	} else if handleN > 0 {
		return Agent{}, "", fmt.Errorf("agent name %q is taken: %w", name, ErrNameTaken)
	}
	key := "at_live_" + randToken(32)
	a := Agent{
		ID:            NewID("agt"),
		Name:          name,
		Email:         name + "@" + s.instance,
		OwnerEmail:    ownerEmail,
		OwnerVerified: verified,
		CreatedAt:     now(),
	}
	if verified {
		a.OwnerVerifiedAt = a.CreatedAt
		a.OwnerVerificationMethod = "operator"
	}
	ownerPendingAt := int64(0)
	if a.OwnerEmail != "" && !a.OwnerVerified {
		ownerPendingAt = a.CreatedAt
	}
	_, err = tx.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,
		owner_verified_at,owner_verification_method,owner_pending_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Email, hashToken(key), a.OwnerEmail, boolInt(a.OwnerVerified),
		a.OwnerVerifiedAt, a.OwnerVerificationMethod, ownerPendingAt, a.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Agent{}, "", fmt.Errorf("agent name %q is taken: %w", name, ErrNameTaken)
		}
		return Agent{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Agent{}, "", err
	}
	return a, key, nil
}

func ValidAgentName(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	var ver, cc int
	err := row.Scan(&a.ID, &a.Name, &a.Email, &a.OwnerEmail, &ver,
		&a.OwnerVerifiedAt, &a.OwnerVerificationMethod, &cc, &a.HumanRecipientsMax,
		&a.Pubkey, &a.AcceptPolicy, &a.PublicContact, &a.PersonID, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.OwnerVerified = ver == 1
	a.AlwaysCCOwner = cc == 1
	return a, err
}

const agentCols = `id,name,email,owner_email,owner_verified,owner_verified_at,owner_verification_method,always_cc_owner,human_recipients_max,pubkey,accept_policy,public_contact,person_id,created_at`

// AgentByKey resolves an API key to its agent.
func (s *Store) AgentByKey(key string) (Agent, error) {
	return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents WHERE key_hash=?`, hashToken(key)))
}

// AgentByName resolves an agent by name (the address localpart).
func (s *Store) AgentByName(name string) (Agent, error) {
	return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents WHERE name=?`, strings.ToLower(name)))
}

// AgentByID resolves an agent by id.
func (s *Store) AgentByID(id string) (Agent, error) {
	return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id=?`, id))
}

// CountAgentsByOwner counts agents whose nominated mailbox was actually proven
// by email. Unverified claims and operator assertions do not consume a human
// mailbox's cap.
func (s *Store) CountAgentsByOwner(owner string) (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM agents WHERE owner_email<>''
		AND owner_verified=1 AND owner_verification_method='email' AND LOWER(owner_email)=LOWER(?)`,
		strings.TrimSpace(owner)).Scan(&n)
	return n, err
}

// RotateKey issues a new API key for the agent; the old one dies now.
func (s *Store) RotateKey(agentID string) (string, error) {
	key := "at_live_" + randToken(32)
	res, err := s.DB.Exec(`UPDATE agents SET key_hash=? WHERE id=?`, hashToken(key), agentID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return key, nil
}

// SetOwnerPending sets (or replaces) the candidate owner mailbox and clears
// all verification provenance. Existing files are left alone; a verification
// transition may grant persistence, but starting a new challenge must not
// destructively shorten already-earned retention.
func (s *Store) SetOwnerPending(agentID, email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("owner email is required")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A challenge authenticates the mailbox that existed when it was minted.
	// Replacing that mailbox must invalidate every older challenge atomically,
	// or an old link could verify the newly supplied address.
	if _, err := tx.Exec(`DELETE FROM verify_tokens WHERE agent_id=?`, agentID); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE agents SET owner_email=?, owner_verified=0,
		owner_verified_at=0, owner_verification_method='', owner_pending_at=? WHERE id=?`, email, now(), agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// MarkOwnerVerifiedBy records how ownership was established and lifts the
// unverified storage tier in the same transaction. "email" means a mailbox
// challenge completed; "operator" is an administrative assertion and does
// not satisfy Agent.HumanVerified; "legacy" exists only for migration/backfill
// and also requires a fresh email challenge before hosting.
func (s *Store) MarkOwnerVerifiedBy(agentID, method string) error {
	switch method {
	case "email", "operator", "legacy":
	default:
		return fmt.Errorf("unknown owner verification method %q", method)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE agents SET owner_verified=1,
		owner_verified_at=?, owner_verification_method=?, owner_pending_at=0 WHERE id=?`, now(), method, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE files SET expires_at=0 WHERE agent_id=? AND claimed=1`, agentID); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkOwnerVerified is the compatibility/admin path. Callers handling a
// completed email challenge should use MarkOwnerVerifiedBy(agentID, "email").
func (s *Store) MarkOwnerVerified(agentID string) error {
	return s.MarkOwnerVerifiedBy(agentID, "operator")
}

// DeleteAgent removes an agent and everything it owns — files, links, inbox,
// recipient circle, upload requests, apps/deployments, counters, idempotency + verify tokens —
// EXCEPT its receipts: the signed chain is append-only and must outlive the
// account, or it stops being deletion-evident. Blob refs held by the agent's
// files and active links are released (only this agent's contribution, so
// content deduped with another agent survives), and the active link tokens are
// returned so the caller can sever any in-flight downloads. All in one
// transaction: a partial cascade would leave dangling refs or FK orphans.
func (s *Store) DeleteAgent(agentID string) (Agent, []string, error) {
	a, err := s.AgentByID(agentID)
	if err != nil {
		return Agent{}, nil, err
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return a, nil, err
	}
	defer tx.Rollback()

	// Active links may have live downloads — return their tokens so the caller
	// can sever them.
	lrows, err := tx.Query(`SELECT token FROM links WHERE agent_id=? AND status='active'`, agentID)
	if err != nil {
		return a, nil, err
	}
	var activeTokens []string
	for lrows.Next() {
		var tok string
		if err := lrows.Scan(&tok); err != nil {
			lrows.Close()
			return a, nil, err
		}
		activeTokens = append(activeTokens, tok)
	}
	lrows.Close()

	// counters and verify_tokens overload agent_id (connect egress metering,
	// connect verification tokens) so they carry no agents FK — delete them
	// explicitly. Every genuinely agent-scoped table has ON DELETE CASCADE, so
	// deleting the agent row removes files, links, messages, webhooks,
	// idempotency, human_recipients, and upload_requests with it. Receipts are
	// pointedly absent — they key on actor email, not agent id, and stay. Blobs
	// are reclaimed by orphan GC once unreferenced.
	for _, q := range []string{
		`DELETE FROM counters WHERE agent_id=?`,
		`DELETE FROM verify_tokens WHERE agent_id=?`,
		`DELETE FROM agents WHERE id=?`,
	} {
		if _, err := tx.Exec(q, agentID); err != nil {
			return a, nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return a, nil, err
	}
	return a, activeTokens, nil
}

type StaleAgentDeletion struct {
	Agent        Agent
	ActiveTokens []string
}

// SweepStaleUnverifiedOwnerAgents removes abandoned mailbox nominations after
// their own pending window. The eligibility predicate is rechecked in the
// delete transaction, so a verification that commits first always wins. Flat
// and fleet agents are both covered; a subsequent pending-person sweep releases
// any now-empty unverified handle.
func (s *Store) SweepStaleUnverifiedOwnerAgents(ttlSeconds int64) ([]StaleAgentDeletion, error) {
	cutoff := now() - ttlSeconds
	rows, err := s.DB.Query(`SELECT id FROM agents WHERE owner_email<>'' AND owner_verified=0
		AND owner_pending_at>0 AND owner_pending_at<=?`, cutoff)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var deleted []StaleAgentDeletion
	for _, id := range ids {
		tx, err := s.DB.Begin()
		if err != nil {
			return deleted, err
		}
		a, err := scanAgent(tx.QueryRow(`SELECT `+agentCols+` FROM agents WHERE id=?
			AND owner_email<>'' AND owner_verified=0 AND owner_pending_at>0 AND owner_pending_at<=?`, id, cutoff))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			continue
		}
		if err != nil {
			tx.Rollback()
			return deleted, err
		}
		lrows, err := tx.Query(`SELECT token FROM links WHERE agent_id=? AND status='active'`, id)
		if err != nil {
			tx.Rollback()
			return deleted, err
		}
		var tokens []string
		for lrows.Next() {
			var token string
			if err := lrows.Scan(&token); err != nil {
				lrows.Close()
				tx.Rollback()
				return deleted, err
			}
			tokens = append(tokens, token)
		}
		if err := lrows.Err(); err != nil {
			lrows.Close()
			tx.Rollback()
			return deleted, err
		}
		if err := lrows.Close(); err != nil {
			tx.Rollback()
			return deleted, err
		}
		for _, q := range []string{
			`DELETE FROM counters WHERE agent_id=?`,
			`DELETE FROM verify_tokens WHERE agent_id=?`,
		} {
			if _, err := tx.Exec(q, id); err != nil {
				tx.Rollback()
				return deleted, err
			}
		}
		res, err := tx.Exec(`DELETE FROM agents WHERE id=? AND owner_verified=0
			AND owner_pending_at>0 AND owner_pending_at<=?`, id, cutoff)
		if err != nil {
			tx.Rollback()
			return deleted, err
		}
		if changed, _ := res.RowsAffected(); changed != 1 {
			tx.Rollback()
			continue
		}
		if err := tx.Commit(); err != nil {
			return deleted, err
		}
		deleted = append(deleted, StaleAgentDeletion{Agent: a, ActiveTokens: tokens})
	}
	return deleted, nil
}

// SetAlwaysCC sets the per-agent "always CC my owner" flag.
func (s *Store) SetAlwaysCC(agentID string, v bool) error {
	_, err := s.DB.Exec(`UPDATE agents SET always_cc_owner=? WHERE id=?`, boolInt(v), agentID)
	return err
}

// SetPubkey publishes the agent's X25519 recipient ("age1...") for sealed
// transfers (or clears it with "").
func (s *Store) SetPubkey(agentID, pubkey string) error {
	res, err := s.DB.Exec(`UPDATE agents SET pubkey=? WHERE id=?`, strings.TrimSpace(pubkey), agentID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return nil
}

// SetHumanRecipientsMax sets the per-agent recipient-circle override
// (0 = instance default, <0 = unlimited).
func (s *Store) SetHumanRecipientsMax(agentID string, n int64) error {
	res, err := s.DB.Exec(`UPDATE agents SET human_recipients_max=? WHERE id=?`, n, agentID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- recipient circle ----
//
// Every unique remote (non-local, non-owner) address an agent emails is
// remembered; the set is capped so a compromised or prompt-injected agent can
// reach at most a handful of strangers. Same-instance agents and the verified
// owner never count.

// CountHumanRecipients returns the number of unique remote recipients the
// agent has claimed.
func (s *Store) CountHumanRecipients(agentID string) (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM human_recipients WHERE agent_id=?`, agentID).Scan(&n)
	return n, err
}

// ClaimHumanRecipients records addrs in the agent's recipient circle,
// enforcing max (<0 = unlimited) atomically. It returns the addresses this
// call newly claimed, so a failed send can release exactly those.
func (s *Store) ClaimHumanRecipients(agentID string, addrs []string, max int64) (newly []string, err error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var used int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM human_recipients WHERE agent_id=?`, agentID).Scan(&used); err != nil {
		return nil, err
	}
	ts := now()
	for _, addr := range addrs {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr == "" {
			continue
		}
		var one int
		err := tx.QueryRow(`SELECT 1 FROM human_recipients WHERE agent_id=? AND addr=?`, agentID, addr).Scan(&one)
		if err == nil {
			continue // already in the circle
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if max >= 0 && used >= max {
			return nil, fmt.Errorf("%w: %d unique remote recipients already used (max %d)", ErrCircleFull, used, max)
		}
		if _, err := tx.Exec(`INSERT INTO human_recipients(agent_id,addr,created_at) VALUES(?,?,?)`, agentID, addr, ts); err != nil {
			return nil, err
		}
		used++
		newly = append(newly, addr)
	}
	return newly, tx.Commit()
}

// ReleaseHumanRecipients removes addresses from the agent's circle — used to
// refund slots claimed for a send that then failed at the relay.
func (s *Store) ReleaseHumanRecipients(agentID string, addrs []string) error {
	for _, addr := range addrs {
		if _, err := s.DB.Exec(`DELETE FROM human_recipients WHERE agent_id=? AND addr=?`, agentID, strings.ToLower(strings.TrimSpace(addr))); err != nil {
			return err
		}
	}
	return nil
}

// ---- suppression (unsubscribe) ----

// Suppress records that addr never wants agent mail from this instance again.
func (s *Store) Suppress(addr string) error {
	_, err := s.DB.Exec(`INSERT INTO suppressed(addr,created_at) VALUES(?,?) ON CONFLICT(addr) DO NOTHING`,
		strings.ToLower(strings.TrimSpace(addr)), now())
	return err
}

// IsSuppressed reports whether addr has unsubscribed from this instance.
func (s *Store) IsSuppressed(addr string) bool {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM suppressed WHERE addr=?`, strings.ToLower(strings.TrimSpace(addr))).Scan(&one)
	return err == nil
}

// UnsubscribeToken returns a stateless HMAC token binding addr to this
// instance's key, so unsubscribe links can't be forged to suppress a victim.
func (s *Store) UnsubscribeToken(addr string) string {
	mac := hmac.New(sha256.New, s.signKey.Seed())
	mac.Write([]byte("unsubscribe:" + strings.ToLower(strings.TrimSpace(addr))))
	return hex.EncodeToString(mac.Sum(nil))
}

// CheckUnsubscribeToken verifies an unsubscribe token for addr.
func (s *Store) CheckUnsubscribeToken(addr, tok string) bool {
	want := s.UnsubscribeToken(addr)
	return subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(strings.TrimSpace(tok)))) == 1
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const maxInt64 = int64(^uint64(0) >> 1)

func addStorageBytes(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > maxInt64-b {
		return 0, fmt.Errorf("invalid or overflowing storage byte count: %d + %d", a, b)
	}
	return a + b, nil
}

func storageBytesExceed(used, additional, limit int64) bool {
	if used < 0 || additional < 0 || limit < 0 || used > limit {
		return true
	}
	return additional > limit-used
}

// ---- disk guard ----

// SetDiskReserve sets the free-space floor (bytes) below which DiskFull
// reports true. 0 disables the guard.
func (s *Store) SetDiskReserve(bytes int64) {
	s.diskWriteMu.Lock()
	s.diskReserve = bytes
	s.diskWriteMu.Unlock()
}

func (s *Store) currentVolumeStats() (int64, int64, error) {
	return s.volumeStatsAt(s.dataDir)
}

func (s *Store) volumeStatsAt(path string) (int64, int64, error) {
	stats := s.volumeStats
	if stats == nil {
		stats = VolumeStats
	}
	return stats(path)
}

// DiskFull reports whether the volume holding the data dir is below the
// configured free-space reserve — the global backstop that keeps the disk
// from ever reaching 100% (where SQLite writes start failing and the whole
// instance falls over). Callers refuse new uploads while it holds.
func (s *Store) DiskFull() bool {
	s.diskWriteMu.Lock()
	reserve := s.diskReserve
	pending := s.diskPending
	s.diskWriteMu.Unlock()
	if reserve <= 0 {
		return false
	}
	free, _, err := s.currentVolumeStats()
	if err != nil {
		return false // can't measure — never lock the instance out on that
	}
	return free-pending < reserve
}

// DiskStats returns the data-dir volume's free and total bytes plus the
// configured reserve (0 = guard disabled). free/total are 0 when the
// platform can't report them.
func (s *Store) DiskStats() (free, total, reserve int64) {
	return s.DiskStatsAt(s.dataDir)
}

// DiskStatsAt is DiskStats for another service-owned path. It is used for
// derived app build contexts, which operators may place on a separate volume.
func (s *Store) DiskStatsAt(path string) (free, total, reserve int64) {
	free, total, _ = s.volumeStatsAt(path)
	s.diskWriteMu.Lock()
	reserve = s.diskReserve
	s.diskWriteMu.Unlock()
	return free, total, reserve
}

// ---- blobs ----

func (s *Store) blobPath(sha string) string {
	return filepath.Join(s.dataDir, "blobs", sha[:2], sha[2:])
}

// PutBlob streams r to disk while hashing, capped at limit bytes. Identical
// content is stored once (content addressing); re-putting an existing blob
// just refreshes its row.
func (s *Store) PutBlob(r io.Reader, limit int64) (sha string, size int64, err error) {
	tmp, err := os.CreateTemp(filepath.Join(s.dataDir, "blobs"), "tmp-*")
	if err != nil {
		return "", 0, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	h := sha256.New()
	writer := &diskGuardBlobWriter{s: s, file: tmp, hash: h}
	size, err = io.CopyBuffer(writer, io.LimitReader(r, limit+1), make([]byte, 1<<20))
	if err != nil {
		return "", 0, err
	}
	if size > limit {
		return "", 0, ErrQuota
	}
	sha = hex.EncodeToString(h.Sum(nil))

	// Finalize under blobMu so the orphan GC can't interleave its row-delete +
	// unlink between the row write and the byte write. The row goes in FIRST,
	// refreshing created_at on dedup: a fresh created_at puts the sha back
	// inside the GC grace window, covering the gap until the caller takes its
	// reference (AddFile/CreateLink, moments later).
	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	if _, err := s.DB.Exec(`INSERT INTO blobs(sha256,size,created_at) VALUES(?,?,?)
		ON CONFLICT(sha256) DO UPDATE SET created_at=excluded.created_at`, sha, size, now()); err != nil {
		return "", 0, err
	}
	dst := s.blobPath(sha)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	if _, statErr := os.Stat(dst); statErr != nil {
		if err := tmp.Sync(); err != nil {
			return "", 0, err
		}
		if err := os.Rename(tmp.Name(), dst); err != nil {
			return "", 0, err
		}
	}
	return sha, size, nil
}

type diskGuardBlobWriter struct {
	s    *Store
	file *os.File
	hash io.Writer
}

func (w *diskGuardBlobWriter) Write(p []byte) (int, error) {
	n, err := w.s.WriteWithDiskReserve(w.s.dataDir, w.file, p)
	if n > 0 {
		if _, hashErr := w.hash.Write(p[:n]); err == nil && hashErr != nil {
			err = hashErr
		}
	}
	return n, err
}

// WriteWithDiskReserve admits and performs one filesystem write without
// allowing concurrent blob or build-context streams to spend the same free
// headroom. path identifies the volume containing dst.
func (s *Store) WriteWithDiskReserve(path string, dst io.Writer, p []byte) (int, error) {
	release, err := s.admitDiskWriteAt(path, int64(len(p)))
	if err != nil {
		return 0, err
	}
	defer release()
	return dst.Write(p)
}

// admitDiskWrite reserves one pending filesystem write against the measured
// free-space floor. The reservation spans the unlocked Write call and is
// released only afterward, when allocation is observable to the next statfs.
func (s *Store) admitDiskWrite(size int64) (func(), error) {
	return s.admitDiskWriteAt(s.dataDir, size)
}

func (s *Store) admitDiskWriteAt(path string, size int64) (func(), error) {
	noop := func() {}
	s.diskWriteMu.Lock()
	if s.diskReserve <= 0 {
		s.diskWriteMu.Unlock()
		return noop, nil
	}
	free, _, statErr := s.volumeStatsAt(path)
	if statErr == nil && free-s.diskReserve-s.diskPending < size {
		s.diskWriteMu.Unlock()
		return nil, ErrDiskReserve
	}
	s.diskPending += size
	s.diskWriteMu.Unlock()
	return func() {
		s.diskWriteMu.Lock()
		s.diskPending -= size
		s.diskWriteMu.Unlock()
	}, nil
}

// OpenBlob opens a blob for reading.
func (s *Store) OpenBlob(sha string) (*os.File, error) {
	if len(sha) < 3 || strings.ContainsAny(sha, "/\\.") {
		return nil, ErrNotFound
	}
	f, err := os.Open(s.blobPath(sha))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return f, err
}

// blobReferencedSQL is the predicate for "some row still points at this blob."
// Orphan GC deletes blobs matching none of these. Every blob-holding table must
// appear here — kept in one place so a new kind of reference can't be forgotten.
const blobReferencedSQL = `EXISTS (SELECT 1 FROM files WHERE files.sha256=blobs.sha256)
	OR EXISTS (SELECT 1 FROM links WHERE links.sha256=blobs.sha256 AND status='active')
	OR EXISTS (SELECT 1 FROM space_events WHERE space_events.sha256=blobs.sha256)
	OR EXISTS (SELECT 1 FROM app_deployments WHERE app_deployments.source_sha256=blobs.sha256)
	OR EXISTS (SELECT 1 FROM app_files WHERE app_files.sha256=blobs.sha256)`

// DeleteOrphanBlobs removes blobs no longer referenced by any file or active
// link, from db and disk. Reference-ness is computed on demand — there is no
// refcount column to keep consistent, so a committed row always protects its
// blob.
//
// Safety has three layers. The grace period skips young rows: PutBlob inserts
// (or refreshes) the row moments before its first file/link reference lands, so
// a fresh created_at keeps a not-yet-referenced blob out of GC. The row DELETE
// re-checks the reference predicate AND age, so a blob referenced or re-put
// since the scan is left alone. Each candidate is rechecked in a transaction
// and atomically renamed to a same-filesystem tomb before metadata is deleted.
// A failed DB delete/commit renames it back; after commit the tomb is unlinked.
// Tombs left by a crash are reconciled on the next run (restored when their DB
// row remains, removed otherwise). blobMu prevents PutBlob from interleaving.
func (s *Store) DeleteOrphanBlobs() (int, error) {
	s.blobMu.Lock()
	tombErr := s.reconcileBlobTombs()
	s.blobMu.Unlock()
	if tombErr != nil {
		return 0, tombErr
	}
	grace := now() - 300
	rows, err := s.DB.Query(`SELECT sha256 FROM blobs WHERE created_at<=? AND NOT (`+blobReferencedSQL+`)`, grace)
	if err != nil {
		return 0, err
	}
	var shas []string
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			rows.Close()
			return 0, err
		}
		shas = append(shas, sha)
	}
	rows.Close()
	n := 0
	var firstErr error
	for _, sha := range shas {
		s.blobMu.Lock()
		tx, txErr := s.DB.Begin()
		if txErr == nil {
			var one int
			txErr = tx.QueryRow(`SELECT 1 FROM blobs WHERE sha256=? AND created_at<=?
				AND NOT (`+blobReferencedSQL+`)`, sha, grace).Scan(&one)
			if errors.Is(txErr, sql.ErrNoRows) {
				txErr = nil // candidate gained a reference or was refreshed
				tx.Rollback()
			} else if txErr == nil {
				src := s.blobPath(sha)
				tombDir := filepath.Join(s.dataDir, "blob-tombs")
				tomb := filepath.Join(tombDir, sha+"."+randToken(6))
				renamed := false
				if txErr = os.MkdirAll(tombDir, 0o700); txErr == nil {
					var info os.FileInfo
					info, txErr = os.Lstat(src)
					if os.IsNotExist(txErr) {
						txErr = nil // metadata-only orphan from an older failure
					} else if txErr == nil && !info.Mode().IsRegular() {
						txErr = fmt.Errorf("blob path %s is not a regular file", src)
					} else if txErr == nil {
						txErr = os.Rename(src, tomb)
						if txErr == nil {
							renamed = true
						}
					}
				}
				if txErr == nil {
					var res sql.Result
					res, txErr = tx.Exec(`DELETE FROM blobs WHERE sha256=?`, sha)
					if txErr == nil {
						if deleted, _ := res.RowsAffected(); deleted != 1 {
							txErr = fmt.Errorf("delete blob metadata changed %d rows", deleted)
						}
					}
				}
				committed := false
				commitAttempted := false
				if txErr == nil {
					commitAttempted = true
					commitErr := tx.Commit()
					if commitErr == nil {
						committed = true
					} else {
						committed, txErr = s.resolveAmbiguousBlobCommit(sha, src, tomb, renamed, commitErr)
					}
				} else {
					tx.Rollback()
				}
				if txErr != nil && renamed && !committed && !commitAttempted {
					if restoreErr := os.Rename(tomb, src); restoreErr != nil {
						txErr = fmt.Errorf("%v; restore blob after DB failure: %w", txErr, restoreErr)
					}
				} else if committed {
					n++
					if renamed {
						if unlinkErr := os.Remove(tomb); unlinkErr != nil && !os.IsNotExist(unlinkErr) {
							txErr = unlinkErr // next run retries tomb cleanup
						}
					}
				}
			} else {
				tx.Rollback()
			}
		}
		s.blobMu.Unlock()
		if txErr != nil && firstErr == nil {
			firstErr = txErr
		}
	}
	return n, firstErr
}

// resolveAmbiguousBlobCommit determines whether a failed Commit call actually
// committed. SQLite can report a commit error after the durable outcome is no
// longer safely inferable from that call alone. The metadata row is the source
// of truth: restore a tomb only while the row survives; if the row is gone,
// treat the delete as committed and discard the tomb. A failed recheck leaves
// the tomb in place for reconcileBlobTombs instead of guessing.
func (s *Store) resolveAmbiguousBlobCommit(sha, src, tomb string, renamed bool, commitErr error) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM blobs WHERE sha256=?`, sha).Scan(&one)
	switch {
	case err == nil:
		if renamed {
			if restoreErr := os.Rename(tomb, src); restoreErr != nil {
				return false, fmt.Errorf("%v; restore blob after ambiguous DB failure: %w", commitErr, restoreErr)
			}
		}
		return false, commitErr
	case errors.Is(err, sql.ErrNoRows):
		if renamed {
			if unlinkErr := os.Remove(tomb); unlinkErr != nil && !os.IsNotExist(unlinkErr) {
				return true, unlinkErr
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("%v; determine blob commit outcome: %w", commitErr, err)
	}
}

// reconcileBlobTombs completes or rolls back a GC operation interrupted after
// the filesystem rename. A surviving metadata row means the transaction did
// not commit and the bytes belong at their canonical path; no row means the
// committed tomb can be discarded.
func (s *Store) reconcileBlobTombs() error {
	dir := filepath.Join(s.dataDir, "blob-tombs")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		sha, _, ok := strings.Cut(entry.Name(), ".")
		if !ok || sha == "" {
			continue
		}
		tomb := filepath.Join(dir, entry.Name())
		var one int
		err := s.DB.QueryRow(`SELECT 1 FROM blobs WHERE sha256=?`, sha).Scan(&one)
		switch {
		case err == nil:
			dst := s.blobPath(sha)
			if _, statErr := os.Stat(dst); os.IsNotExist(statErr) {
				if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
					return err
				}
				if err := os.Rename(tomb, dst); err != nil {
					return err
				}
			} else if statErr != nil {
				return statErr
			} else if err := os.Remove(tomb); err != nil && !os.IsNotExist(err) {
				return err
			}
		case errors.Is(err, sql.ErrNoRows):
			if err := os.Remove(tomb); err != nil && !os.IsNotExist(err) {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

// ---- files (the folder) ----

// AddFile records a folder entry over an existing blob. Re-adding the same
// (name, sha) refreshes the row instead of duplicating it. The blob is kept
// alive simply by this row existing (orphan GC computes reference-ness).
func (s *Store) AddFile(agentID, sha, name, mime string, size int64, source string, claimed bool, expiresAt int64) (File, error) {
	f := File{
		ID: NewID("fil"), AgentID: agentID, SHA256: sha, Name: safeName(name), MIME: mime,
		Size: size, Source: source, Claimed: claimed, ExpiresAt: expiresAt, CreatedAt: now(),
	}
	if _, err := s.DB.Exec(`INSERT INTO files(id,agent_id,sha256,name,mime,size,source,claimed,expires_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id,name,sha256) DO UPDATE SET
			claimed=MAX(files.claimed,excluded.claimed),
			expires_at=CASE
				WHEN files.claimed=1 AND excluded.claimed=0 THEN files.expires_at
				ELSE excluded.expires_at
			END`,
		f.ID, f.AgentID, f.SHA256, f.Name, f.MIME, f.Size, f.Source, boolInt(f.Claimed), f.ExpiresAt, f.CreatedAt); err != nil {
		return f, err
	}
	// Return the canonical row (whether freshly inserted or already present).
	row := s.DB.QueryRow(`SELECT `+fileCols+` FROM files WHERE agent_id=? AND name=? AND sha256=?`, agentID, f.Name, sha)
	return scanFile(row)
}

// AgentHasFile reports whether the agent's folder already holds this exact
// (name, sha) entry — used to waive quota on idempotent re-uploads.
func (s *Store) AgentHasFile(agentID, sha, name string) bool {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM files WHERE agent_id=? AND sha256=? AND name=?`, agentID, sha, safeName(name)).Scan(&one)
	return err == nil
}

const fileCols = `id,agent_id,sha256,name,mime,size,source,claimed,expires_at,created_at`

func scanFile(row interface{ Scan(...any) error }) (File, error) {
	var f File
	var claimed int
	err := row.Scan(&f.ID, &f.AgentID, &f.SHA256, &f.Name, &f.MIME, &f.Size, &f.Source, &claimed, &f.ExpiresAt, &f.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	f.Claimed = claimed == 1
	return f, err
}

func safeName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." || name == "/" {
		name = "upload.bin"
	}
	if len(name) > 255 {
		name = name[len(name)-255:]
	}
	return name
}

// ListFiles returns the agent's folder, newest first.
func (s *Store) ListFiles(agentID string) ([]File, error) {
	rows, err := s.DB.Query(`SELECT `+fileCols+` FROM files WHERE agent_id=? ORDER BY created_at DESC, id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FileBySHA fetches an agent's folder entry by content hash.
func (s *Store) FileBySHA(agentID, sha string) (File, error) {
	return scanFile(s.DB.QueryRow(`SELECT `+fileCols+` FROM files WHERE agent_id=? AND sha256=? ORDER BY created_at DESC LIMIT 1`, agentID, sha))
}

// FileByName fetches an agent's folder entry by filename.
func (s *Store) FileByName(agentID, name string) (File, error) {
	return scanFile(s.DB.QueryRow(`SELECT `+fileCols+` FROM files WHERE agent_id=? AND name=? ORDER BY created_at DESC LIMIT 1`, agentID, name))
}

// FileEntry fetches one exact folder name/content pair.
func (s *Store) FileEntry(agentID, sha, name string) (File, error) {
	return scanFile(s.DB.QueryRow(`SELECT `+fileCols+` FROM files
		WHERE agent_id=? AND sha256=? AND name=? LIMIT 1`, agentID, sha, safeName(name)))
}

// DeleteFile removes folder entries for a hash. It returns the removed entries;
// the blob is reclaimed by orphan GC once nothing references it.
func (s *Store) DeleteFile(agentID, sha string) ([]File, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT `+fileCols+` FROM files WHERE agent_id=? AND sha256=?`, agentID, sha)
	if err != nil {
		return nil, err
	}
	var files []File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, ErrNotFound
	}
	res, err := tx.Exec(`DELETE FROM files WHERE agent_id=? AND sha256=?`, agentID, sha)
	if err != nil {
		return nil, err
	}
	deleted, _ := res.RowsAffected()
	if deleted != int64(len(files)) {
		return nil, fmt.Errorf("delete file changed %d rows after selecting %d", deleted, len(files))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return files, nil
}

// DeleteFileEntry removes one exact folder entry. It is used for temporary
// staging rows whose blob may legitimately also appear under another name;
// unlike DeleteFile it never broadens a precise cleanup into deleting every
// same-content entry.
func (s *Store) DeleteFileEntry(agentID, sha, name string) (File, error) {
	f, err := scanFile(s.DB.QueryRow(`SELECT `+fileCols+` FROM files
		WHERE agent_id=? AND sha256=? AND name=? LIMIT 1`, agentID, sha, safeName(name)))
	if err != nil {
		return f, err
	}
	res, err := s.DB.Exec(`DELETE FROM files WHERE id=? AND agent_id=?`, f.ID, agentID)
	if err != nil {
		return f, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return f, ErrNotFound
	}
	return f, nil
}

// KeepFile claims a file. expiresAt caps its remaining lifetime: 0 makes it
// persistent (verified owners); unverified agents pass their tier's ceiling —
// keeping must not grant an immortality their own uploads don't get.
func (s *Store) KeepFile(agentID, sha string, expiresAt int64) (File, error) {
	res, err := s.DB.Exec(`UPDATE files SET claimed=1, expires_at=? WHERE agent_id=? AND sha256=?`, expiresAt, agentID, sha)
	if err != nil {
		return File{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return File{}, ErrNotFound
	}
	return s.FileBySHA(agentID, sha)
}

// StorageUsed sums distinct blobs attributable to an agent: anything in its
// folder or active links, plus every file pinned by a space it owns. Charging
// all space storage to the durable owner_id avoids tying accounting to actor
// email strings, which can be deleted and later re-registered by an unrelated
// identity. A blob present in several places is counted only once.
func (s *Store) StorageUsed(agentID string) (int64, error) {
	var n sql.NullInt64
	err := s.DB.QueryRow(`SELECT SUM(b.size) FROM blobs b WHERE
		EXISTS (SELECT 1 FROM files f WHERE f.agent_id=? AND f.sha256=b.sha256)
		OR EXISTS (SELECT 1 FROM links l WHERE l.agent_id=? AND l.sha256=b.sha256
			AND l.status='active' AND l.expires_at>?)
		OR EXISTS (SELECT 1 FROM space_events e JOIN spaces sp ON sp.id=e.space_id
			WHERE e.kind='file' AND e.sha256=b.sha256 AND sp.owner_id=?)`,
		agentID, agentID, now(), agentID).Scan(&n)
	if err != nil {
		return 0, err
	}
	if n.Int64 < 0 {
		return 0, fmt.Errorf("invalid negative storage usage %d", n.Int64)
	}
	return n.Int64, nil
}

// AgentUsesStorageBlob reports whether sha is already part of the agent's
// logical storage charge. Adding another folder name for already-charged bytes
// must not consume the blob's size a second time.
func (s *Store) AgentUsesStorageBlob(agentID, sha string) (bool, error) {
	var one int
	err := s.DB.QueryRow(`SELECT 1 WHERE
		EXISTS (SELECT 1 FROM files WHERE agent_id=? AND sha256=?)
		OR EXISTS (SELECT 1 FROM links WHERE agent_id=? AND sha256=?
			AND status='active' AND expires_at>?)
		OR EXISTS (SELECT 1 FROM space_events e JOIN spaces sp ON sp.id=e.space_id
			WHERE e.kind='file' AND e.sha256=? AND sp.owner_id=?)`,
		agentID, sha, agentID, sha, now(), sha, agentID).Scan(&one)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

// StorageConsumer is one row of the admin "top storage consumers" view.
type StorageConsumer struct {
	AgentID       string `json:"agent_id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	OwnerEmail    string `json:"owner_email"`
	OwnerVerified bool   `json:"owner_verified"`
	// Files is the number of distinct blobs in this agent's logical transfer
	// charge. The JSON name is retained for API compatibility.
	Files int64 `json:"files"`
	Bytes int64 `json:"bytes"`
}

// TopStorageConsumers ranks the same distinct logical blob set StorageUsed
// enforces: folder rows, unexpired active links, and file events in spaces the
// agent owns. Repeated names/references to one sha count once.
func (s *Store) TopStorageConsumers(limit int) ([]StorageConsumer, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.Query(`WITH charged_refs(agent_id,sha256) AS (
			SELECT agent_id,sha256 FROM files
			UNION
			SELECT agent_id,sha256 FROM links
				WHERE status='active' AND expires_at>?
			UNION
			SELECT sp.owner_id,e.sha256 FROM space_events e
				JOIN spaces sp ON sp.id=e.space_id WHERE e.kind='file'
		), charges AS (
			SELECT r.agent_id,COUNT(*) AS blobs,COALESCE(SUM(b.size),0) AS bytes
			FROM charged_refs r JOIN blobs b ON b.sha256=r.sha256
			GROUP BY r.agent_id
		)
		SELECT a.id,a.name,a.email,a.owner_email,a.owner_verified,
			COALESCE(c.blobs,0),COALESCE(c.bytes,0) AS bytes
		FROM agents a LEFT JOIN charges c ON c.agent_id=a.id
		ORDER BY bytes DESC,a.created_at LIMIT ?`, now(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StorageConsumer{}
	for rows.Next() {
		var c StorageConsumer
		var verified int
		if err := rows.Scan(&c.AgentID, &c.Name, &c.Email, &c.OwnerEmail, &verified, &c.Files, &c.Bytes); err != nil {
			return nil, err
		}
		c.OwnerVerified = verified == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// StoredBytes is the physical footprint: the sum of all blob sizes (dedup
// means this is ≤ the sum of folder entries).
func (s *Store) StoredBytes() (int64, error) {
	var n sql.NullInt64
	err := s.DB.QueryRow(`SELECT SUM(size) FROM blobs`).Scan(&n)
	return n.Int64, err
}

// ExpireFiles removes folder entries past their expiry — unclaimed arrivals
// and unverified-tier uploads alike (expires_at=0 means immortal). It returns
// the expired entries (for receipts).
func (s *Store) ExpireFiles(cutoff int64) ([]File, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT `+fileCols+` FROM files WHERE expires_at>0 AND expires_at<=?`, cutoff)
	if err != nil {
		return nil, err
	}
	var files []File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	expired := files[:0]
	for _, f := range files {
		// Recheck the expiry predicate in the mutation itself. If KeepFile or
		// owner verification committed first, this delete is a no-op; if this
		// transaction commits first, the concurrent keeper observes not-found.
		res, err := tx.Exec(`DELETE FROM files WHERE id=? AND expires_at>0 AND expires_at<=?`, f.ID, cutoff)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // someone else deleted it first
		}
		expired = append(expired, f)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return expired, nil
}

// ---- links ----

// CreateLink mints an ephemeral share link over a blob. The active link keeps
// the blob alive (orphan GC computes reference-ness on demand).
func (s *Store) CreateLink(agentID, sha, name, mime string, size int64, once bool, ttl time.Duration) (Link, error) {
	l := Link{
		Token: NewLinkToken(), AgentID: agentID, SHA256: sha, Name: safeName(name), MIME: mime,
		Size: size, Once: once, Status: "active",
		ExpiresAt: time.Now().Add(ttl).Unix(), CreatedAt: now(),
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return Link{}, err
	}
	defer tx.Rollback()
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM links
		WHERE agent_id=? AND status='active' AND expires_at>?`, agentID, now()).Scan(&live); err != nil {
		return Link{}, err
	}
	if live >= MaxActiveLinksPerAgent {
		return Link{}, fmt.Errorf("%w: at most %d active links per agent", ErrLimit, MaxActiveLinksPerAgent)
	}
	_, err = tx.Exec(`INSERT INTO links(token,agent_id,sha256,name,mime,size,once,downloads,status,expires_at,created_at)
		VALUES(?,?,?,?,?,?,?,0,'active',?,?)`,
		l.Token, l.AgentID, l.SHA256, l.Name, l.MIME, l.Size, boolInt(l.Once), l.ExpiresAt, l.CreatedAt)
	if err != nil {
		return l, err
	}
	return l, tx.Commit()
}

const linkCols = `token,agent_id,sha256,name,mime,size,once,downloads,status,expires_at,created_at`

func scanLink(row interface{ Scan(...any) error }) (Link, error) {
	var l Link
	var once int
	err := row.Scan(&l.Token, &l.AgentID, &l.SHA256, &l.Name, &l.MIME, &l.Size, &once, &l.Downloads, &l.Status, &l.ExpiresAt, &l.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	l.Once = once == 1
	return l, err
}

// GetLink fetches a link by token.
func (s *Store) GetLink(token string) (Link, error) {
	return scanLink(s.DB.QueryRow(`SELECT `+linkCols+` FROM links WHERE token=?`, token))
}

// ListLinks returns the agent's links, newest first.
func (s *Store) ListLinks(agentID string) ([]Link, error) {
	rows, err := s.DB.Query(`SELECT `+linkCols+` FROM links WHERE agent_id=? ORDER BY created_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// closeLink transitions an active link to a terminal status. Once it's no
// longer active it stops keeping its blob alive; orphan GC reclaims the bytes
// if nothing else references them.
func (s *Store) closeLink(token, status string) (Link, error) {
	l, err := s.GetLink(token)
	if err != nil {
		return l, err
	}
	if l.Status != "active" {
		return l, ErrNotFound
	}
	res, err := s.DB.Exec(`UPDATE links SET status=? WHERE token=? AND status='active'`, status, token)
	if err != nil {
		return l, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return l, ErrNotFound // lost the race to another closer
	}
	l.Status = status
	return l, nil
}

// RevokeLink kills a link now.
func (s *Store) RevokeLink(token string) (Link, error) { return s.closeLink(token, "revoked") }

// BurnLink marks a burn-after-read link consumed.
func (s *Store) BurnLink(token string) (Link, error) { return s.closeLink(token, "burned") }

// RevokeLinksForSHA revokes all of an agent's active links over a hash.
func (s *Store) RevokeLinksForSHA(agentID, sha string) ([]Link, error) {
	rows, err := s.DB.Query(`SELECT token FROM links WHERE agent_id=? AND sha256=? AND status='active'`, agentID, sha)
	if err != nil {
		return nil, err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		tokens = append(tokens, t)
	}
	rows.Close()
	var out []Link
	for _, t := range tokens {
		l, err := s.RevokeLink(t)
		if err == nil {
			out = append(out, l)
		}
	}
	return out, nil
}

// ExpireLinks closes active links past expiry and returns them.
func (s *Store) ExpireLinks(cutoff int64) ([]Link, error) {
	rows, err := s.DB.Query(`SELECT token FROM links WHERE status='active' AND expires_at<=?`, cutoff)
	if err != nil {
		return nil, err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		tokens = append(tokens, t)
	}
	rows.Close()
	var out []Link
	for _, t := range tokens {
		l, err := s.closeLink(t, "expired")
		if err == nil {
			out = append(out, l)
		}
	}
	return out, nil
}

// CountDownload bumps a link's download counter.
func (s *Store) CountDownload(token string) error {
	_, err := s.DB.Exec(`UPDATE links SET downloads=downloads+1 WHERE token=?`, token)
	return err
}

// CountActiveDownload claims a download only while the capability remains
// active and unexpired. This is used by inline transports that have buffered
// the body but have not exposed it to their caller yet.
func (s *Store) CountActiveDownload(token string) error {
	res, err := s.DB.Exec(`UPDATE links SET downloads=downloads+1
		WHERE token=? AND status='active' AND expires_at>?`, token, now())
	if err != nil {
		return err
	}
	if changed, _ := res.RowsAffected(); changed != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- messages ----

const messageStorageBytesSQL = `
	LENGTH(CAST(from_addr AS BLOB))+LENGTH(CAST(to_addrs AS BLOB))+
	LENGTH(CAST(subject AS BLOB))+LENGTH(CAST(body AS BLOB))+
	LENGTH(CAST(message_id AS BLOB))+LENGTH(CAST(in_reply_to AS BLOB))+
	LENGTH(CAST(refs AS BLOB))+LENGTH(CAST(manifest AS BLOB))+
	LENGTH(CAST(attachments AS BLOB))+LENGTH(CAST(dkim AS BLOB))+
	LENGTH(CAST(spf AS BLOB))`

// AddMessage inserts an inbox row for an agent. When the durable inbox is at
// its count or byte ceiling, the oldest read messages are evicted in the same
// transaction to make room. Unread messages are never silently discarded.
func (s *Store) AddMessage(m Message) (Message, error) {
	return s.addMessageLimited(m, MaxInboxMessagesPerAgent, MaxInboxBytesPerAgent)
}

// addMessageLimited carries explicit limits so boundary behavior can be tested
// without constructing a 256 MiB fixture. Production always calls AddMessage.
func (s *Store) addMessageLimited(m Message, maxMessages, maxBytes int64) (Message, error) {
	if m.ID == "" {
		m.ID = NewID("msg")
	}
	if m.ReceivedAt == 0 {
		m.ReceivedAt = now()
	}
	toJSON, _ := json.Marshal(m.To)
	attJSON, _ := json.Marshal(m.Attachments)
	if m.Attachments == nil {
		attJSON = []byte("[]")
	}
	incomingBytes := int64(len(m.From) + len(toJSON) + len(m.Subject) + len(m.Text) + len(m.MessageID) +
		len(m.InReplyTo) + len(m.References) + len(m.Manifest) + len(attJSON) + len(m.DKIM) + len(m.SPF))
	if maxMessages <= 0 || maxBytes <= 0 || incomingBytes > maxBytes {
		return m, fmt.Errorf("%w: incoming message is %d bytes (max %d)", ErrInboxFull, incomingBytes, maxBytes)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return m, err
	}
	defer tx.Rollback()
	var count, used int64
	if err := tx.QueryRow(`SELECT COUNT(*),COALESCE(SUM(`+messageStorageBytesSQL+`),0)
		FROM messages WHERE agent_id=?`, m.AgentID).Scan(&count, &used); err != nil {
		return m, err
	}
	if count >= maxMessages || storageBytesExceed(used, incomingBytes, maxBytes) {
		rows, err := tx.Query(`SELECT id,received_at,`+messageStorageBytesSQL+`
			FROM messages WHERE agent_id=? AND read=1 ORDER BY received_at,id`, m.AgentID)
		if err != nil {
			return m, err
		}
		var removed int64
		var cutoffID string
		var cutoffReceived int64
		for rows.Next() {
			var rowBytes int64
			if err := rows.Scan(&cutoffID, &cutoffReceived, &rowBytes); err != nil {
				rows.Close()
				return m, err
			}
			removed++
			count--
			used -= rowBytes
			if count < maxMessages && !storageBytesExceed(used, incomingBytes, maxBytes) {
				break
			}
		}
		if err := rows.Close(); err != nil {
			return m, err
		}
		if count >= maxMessages || storageBytesExceed(used, incomingBytes, maxBytes) {
			return m, fmt.Errorf("%w: unread inbox uses %d messages / %d bytes (max %d / %d)",
				ErrInboxFull, count, used, maxMessages, maxBytes)
		}
		res, err := tx.Exec(`DELETE FROM messages WHERE agent_id=? AND read=1 AND
			(received_at<? OR (received_at=? AND id<=?))`, m.AgentID, cutoffReceived, cutoffReceived, cutoffID)
		if err != nil {
			return m, err
		}
		if n, _ := res.RowsAffected(); n != removed {
			return m, fmt.Errorf("evicted %d read inbox messages, want %d", n, removed)
		}
	}
	_, err = tx.Exec(`INSERT INTO messages(id,agent_id,from_addr,to_addrs,subject,body,message_id,in_reply_to,refs,manifest,attachments,dkim,spf,read,quarantined,received_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)`,
		m.ID, m.AgentID, m.From, string(toJSON), m.Subject, m.Text, m.MessageID, m.InReplyTo, m.References, m.Manifest, string(attJSON), m.DKIM, m.SPF, boolInt(m.Quarantined), m.ReceivedAt)
	if err != nil {
		return m, err
	}
	return m, tx.Commit()
}

const msgCols = `id,agent_id,from_addr,to_addrs,subject,body,message_id,in_reply_to,refs,manifest,attachments,dkim,spf,read,quarantined,received_at`

func scanMessage(row interface{ Scan(...any) error }) (Message, error) {
	var m Message
	var to, att string
	var read, quar int
	err := row.Scan(&m.ID, &m.AgentID, &m.From, &to, &m.Subject, &m.Text, &m.MessageID, &m.InReplyTo, &m.References, &m.Manifest, &att, &m.DKIM, &m.SPF, &read, &quar, &m.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	if err != nil {
		return m, err
	}
	m.Read = read == 1
	m.Quarantined = quar == 1
	_ = json.Unmarshal([]byte(to), &m.To)
	_ = json.Unmarshal([]byte(att), &m.Attachments)
	if m.Attachments == nil {
		m.Attachments = []Attachment{}
	}
	return m, nil
}

// ListInbox returns inbox messages, oldest first. thread may be either the
// inbox row id exposed by this API or an RFC/AgentTransfer message id. When it
// names an inbox row, its wire Message-ID, parent, and References become thread
// needles so selecting a reply still returns ancestors and sibling replies.
func (s *Store) ListInbox(agentID string, unreadOnly bool, thread string, limit int) ([]Message, error) {
	if limit <= 0 {
		limit = DefaultInboxListLimit
	}
	if limit > MaxInboxListLimit {
		limit = MaxInboxListLimit
	}
	where := `agent_id=? AND quarantined=0`
	args := []any{agentID}
	if unreadOnly {
		where += ` AND read=0`
	}
	if thread != "" {
		needles := []string{thread}
		var wireID, inReplyTo, refs string
		if err := s.DB.QueryRow(`SELECT message_id,in_reply_to,refs FROM messages WHERE agent_id=? AND id=?`, agentID, thread).
			Scan(&wireID, &inReplyTo, &refs); err == nil {
			needles = append(needles, wireID, inReplyTo)
			needles = append(needles, strings.Fields(refs)...)
		}
		seen := map[string]bool{}
		clauses := []string{"id=?"}
		threadArgs := []any{thread}
		for _, needle := range needles {
			needle = strings.TrimSpace(needle)
			if needle == "" || len(needle) > 1024 || seen[needle] || len(seen) >= 64 {
				continue
			}
			seen[needle] = true
			clauses = append(clauses, `instr(message_id,?)>0`, `instr(in_reply_to,?)>0`, `instr(refs,?)>0`)
			threadArgs = append(threadArgs, needle, needle, needle)
		}
		where += ` AND (` + strings.Join(clauses, ` OR `) + `)`
		args = append(args, threadArgs...)
	}
	// Select the newest bounded window, then restore chronological wire order.
	// Limiting an ascending query would return the same oldest rows forever and
	// hide every new arrival once a mailbox grows past the default window.
	q := `SELECT ` + msgCols + ` FROM (
		SELECT ` + msgCols + ` FROM messages WHERE ` + where + `
		ORDER BY received_at DESC,id DESC LIMIT ?
	) ORDER BY received_at,id`
	args = append(args, limit)
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListQuarantine returns messages held out of the main inbox by the recipient's
// accept policy (unknown senders), newest first.
func (s *Store) ListQuarantine(agentID string, limit int) ([]Message, error) {
	if limit <= 0 {
		limit = DefaultInboxListLimit
	}
	if limit > MaxInboxListLimit {
		limit = MaxInboxListLimit
	}
	q := `SELECT ` + msgCols + ` FROM messages WHERE agent_id=? AND quarantined=1 ORDER BY received_at DESC, id DESC`
	q += fmt.Sprintf(` LIMIT %d`, limit)
	rows, err := s.DB.Query(q, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Message{}
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMessage fetches one inbox message owned by the agent.
func (s *Store) GetMessage(agentID, id string) (Message, error) {
	return scanMessage(s.DB.QueryRow(`SELECT `+msgCols+` FROM messages WHERE agent_id=? AND id=?`, agentID, id))
}

// HasMessageID reports whether the agent already has a message with this RFC
// Message-ID — used to make at-least-once inbound delivery (connect
// store-and-forward, retried drains) idempotent instead of duplicating.
func (s *Store) HasMessageID(agentID, messageID string) bool {
	if messageID == "" {
		return false
	}
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM messages WHERE agent_id=? AND message_id=? LIMIT 1`, agentID, messageID).Scan(&one)
	return err == nil
}

// MarkRead flags a message read.
func (s *Store) MarkRead(agentID, id string) error {
	res, err := s.DB.Exec(`UPDATE messages SET read=1 WHERE agent_id=? AND id=?`, agentID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- receipts ----

// AppendReceipt signs and appends one receipt to the instance chain.
func (s *Store) AppendReceipt(actor, action, sha string, size int64, target, messageID string) (receipt.Receipt, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	prev, err := s.getSetting("chain_head")
	if err != nil {
		return receipt.Receipt{}, err
	}
	if prev == "" {
		prev = receipt.GenesisPrev
	}
	r := receipt.Receipt{
		V: 1, ID: NewID("rcp"), TS: time.Now().UTC().Format(time.RFC3339Nano),
		Instance: s.Instance(), Actor: actor, Action: action,
		SHA256: sha, Size: size, Target: target, MessageID: messageID, Prev: prev,
	}
	r.Sign(s.signKey)

	tx, err := s.DB.Begin()
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO receipts(id,ts,instance,actor,action,sha256,size,target,message_id,prev,sig) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.TS, r.Instance, r.Actor, r.Action, r.SHA256, r.Size, r.Target, r.MessageID, r.Prev, r.Sig); err != nil {
		return r, err
	}
	if _, err := tx.Exec(`INSERT INTO settings(k,v) VALUES('chain_head',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, r.Hash()); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

func scanReceipt(row interface{ Scan(...any) error }) (receipt.Receipt, error) {
	var r receipt.Receipt
	var seq int64
	err := row.Scan(&seq, &r.ID, &r.TS, &r.Instance, &r.Actor, &r.Action, &r.SHA256, &r.Size, &r.Target, &r.MessageID, &r.Prev, &r.Sig)
	r.V = 1
	return r, err
}

const receiptCols = `seq,id,ts,instance,actor,action,sha256,size,target,message_id,prev,sig`

// ListReceipts returns receipts in chain order (oldest first). actor "" means
// all (admin). A positive limit selects the newest window first, then restores
// ascending order so bounded logs show current activity without reversing the
// receipt sequence clients verify and display.
func (s *Store) ListReceipts(actor string, limit int) ([]receipt.Receipt, error) {
	where := ""
	var args []any
	if actor != "" {
		where = ` WHERE actor=?`
		args = append(args, actor)
	}
	q := `SELECT ` + receiptCols + ` FROM receipts` + where + ` ORDER BY seq`
	if limit > 0 {
		q = `SELECT ` + receiptCols + ` FROM (
			SELECT ` + receiptCols + ` FROM receipts` + where + ` ORDER BY seq DESC LIMIT ?
		) ORDER BY seq`
		args = append(args, limit)
	}
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []receipt.Receipt{}
	for rows.Next() {
		r, err := scanReceipt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- idempotency ----

// schemaIdempotencyV12 replaces response-only records with request-bound
// status/body records. In-flight rows use status=0. Old entries are deliberately
// discarded: they lack a request fingerprint and cannot safely reject key reuse
// with a different payload.
const schemaIdempotencyV12 = `
DROP TABLE idempotency;
CREATE TABLE idempotency (
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status INTEGER NOT NULL DEFAULT 0 CHECK(status=0 OR (status>=100 AND status<=599)),
  response BLOB NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, key)
);
CREATE INDEX idx_idempotency_agent_created ON idempotency(agent_id, created_at);
`

type IdempotencyRecord struct {
	RequestHash string
	Status      int
	Response    []byte
	CreatedAt   int64
}

// BeginIdempotent atomically binds key to requestHash and reserves one bounded
// in-flight record. Existing same-request records are returned for replay;
// different-request reuse is rejected. Expired records are pruned before the
// per-agent ceiling is checked, so invalid unique requests cannot grow SQLite
// without bound.
func (s *Store) BeginIdempotent(agentID, key, requestHash string) (IdempotencyRecord, bool, error) {
	var record IdempotencyRecord
	if key == "" || requestHash == "" {
		return record, false, errors.New("idempotency key and request hash are required")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return record, false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM idempotency WHERE agent_id=? AND created_at<?`,
		agentID, now()-IdempotencyTTLSeconds); err != nil {
		return record, false, err
	}
	err = tx.QueryRow(`SELECT request_hash,status,response,created_at FROM idempotency
		WHERE agent_id=? AND key=?`, agentID, key).
		Scan(&record.RequestHash, &record.Status, &record.Response, &record.CreatedAt)
	if err == nil {
		if record.RequestHash != requestHash {
			return IdempotencyRecord{}, false, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return IdempotencyRecord{}, false, err
		}
		return record, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return record, false, err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM idempotency WHERE agent_id=?`, agentID).Scan(&count); err != nil {
		return record, false, err
	}
	if count >= MaxIdempotencyRowsPerAgent {
		return record, false, fmt.Errorf("%w: at most %d idempotency records per agent", ErrLimit, MaxIdempotencyRowsPerAgent)
	}
	record = IdempotencyRecord{RequestHash: requestHash, CreatedAt: now()}
	if _, err := tx.Exec(`INSERT INTO idempotency(agent_id,key,request_hash,status,response,created_at)
		VALUES(?,?,?,0,'',?)`, agentID, key, requestHash, record.CreatedAt); err != nil {
		return IdempotencyRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IdempotencyRecord{}, false, err
	}
	return record, true, nil
}

// CompleteIdempotent commits the exact HTTP status and JSON bytes for replay.
// Only the request that owns the matching pending reservation may complete it.
func (s *Store) CompleteIdempotent(agentID, key, requestHash string, status int, response []byte) error {
	if status < 100 || status > 599 || len(response) == 0 {
		return errors.New("invalid idempotency response")
	}
	res, err := s.DB.Exec(`UPDATE idempotency SET status=?,response=?
		WHERE agent_id=? AND key=? AND request_hash=? AND status=0`,
		status, response, agentID, key, requestHash)
	if err != nil {
		return err
	}
	if changed, _ := res.RowsAffected(); changed != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- verification tokens ----

// CreateVerifyToken mints an owner-verification token.
func (s *Store) CreateVerifyToken(agentID string) (string, error) {
	tok := randToken(24)
	var ownerEmail string
	_ = s.DB.QueryRow(`SELECT owner_email FROM agents WHERE id=?`, agentID).Scan(&ownerEmail)
	_, err := s.DB.Exec(`INSERT INTO verify_tokens(token,agent_id,created_at,owner_email) VALUES(?,?,?,?)`, tok, agentID, now(), ownerEmail)
	return tok, err
}

// CreateOwnerVerifyToken atomically binds a challenge to the exact mailbox
// that the caller is about to email. The explicit expected address prevents a
// concurrent owner replacement from making a token sent to mailbox A verify
// mailbox B. Generic Connect tokens continue to use CreateVerifyToken above.
func (s *Store) CreateOwnerVerifyToken(agentID, expectedEmail string) (string, error) {
	expectedEmail = strings.TrimSpace(expectedEmail)
	if expectedEmail == "" {
		return "", errors.New("owner email is required")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var currentEmail string
	if err := tx.QueryRow(`SELECT owner_email FROM agents WHERE id=?`, agentID).Scan(&currentEmail); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	if !strings.EqualFold(currentEmail, expectedEmail) {
		return "", errors.New("owner mailbox changed before challenge was created")
	}
	tok := randToken(24)
	if _, err := tx.Exec(`INSERT INTO verify_tokens(token,agent_id,created_at,owner_email) VALUES(?,?,?,?)`,
		tok, agentID, now(), currentEmail); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return tok, nil
}

// PeekVerifyToken resolves a verification token WITHOUT consuming it — the
// GET landing page must be side-effect-free so link prefetchers and mail
// scanners can't verify on the owner's behalf; only the explicit confirm POST
// consumes.
func (s *Store) PeekVerifyToken(tok string) (string, error) {
	var agentID string
	err := s.DB.QueryRow(`SELECT agent_id FROM verify_tokens WHERE token=? AND created_at>=?`, tok, now()-48*3600).Scan(&agentID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return agentID, err
}

// ConsumeVerifyToken redeems a verification token for its agent id.
func (s *Store) ConsumeVerifyToken(tok string) (string, error) {
	var agentID string
	err := s.DB.QueryRow(`DELETE FROM verify_tokens WHERE token=? AND created_at>=? RETURNING agent_id`, tok, now()-48*3600).Scan(&agentID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return agentID, err
}

// VerifyOwnerToken atomically consumes a mailbox challenge and verifies only
// the exact owner address captured when it was minted. If SetOwnerPending won
// a race first, it deleted the token; if it runs afterward, it resets the
// verified bit. Either ordering prevents an old click from blessing a new
// mailbox nomination.
func (s *Store) VerifyOwnerToken(tok string) (string, error) {
	return s.VerifyOwnerTokenLimited(tok, 0)
}

// VerifyOwnerTokenLimited claims a human-verified mailbox slot in the same
// transaction that consumes the challenge and flips owner_verified. Pending
// nominations do not count; maxVerified<=0 is unlimited for operator/internal
// flows. A cap failure rolls the token deletion back so it can be retried after
// the owner frees a verified slot.
func (s *Store) VerifyOwnerTokenLimited(tok string, maxVerified int64) (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var agentID, challengedEmail string
	err = tx.QueryRow(`DELETE FROM verify_tokens WHERE token=? AND created_at>=? RETURNING agent_id,owner_email`,
		tok, now()-48*3600).Scan(&agentID, &challengedEmail)
	if errors.Is(err, sql.ErrNoRows) || challengedEmail == "" || strings.HasPrefix(agentID, "connect:") {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if maxVerified > 0 {
		var verified int64
		if err := tx.QueryRow(`SELECT COUNT(*) FROM agents
			WHERE id<>? AND owner_verified=1 AND owner_verification_method='email'
			AND lower(owner_email)=lower(?)`, agentID, challengedEmail).Scan(&verified); err != nil {
			return "", err
		}
		if verified >= maxVerified {
			return "", fmt.Errorf("%w: mailbox already has %d verified agents (max %d)",
				ErrOwnerAgentLimit, verified, maxVerified)
		}
	}
	res, err := tx.Exec(`UPDATE agents SET owner_verified=1,owner_verified_at=?,
		owner_verification_method='email',owner_pending_at=0
		WHERE id=? AND lower(owner_email)=lower(?)`, now(), agentID, challengedEmail)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE files SET expires_at=0 WHERE agent_id=? AND claimed=1`, agentID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE persons SET verified_at=CASE WHEN verified_at=0 THEN ? ELSE verified_at END
		WHERE id=(SELECT person_id FROM agents WHERE id=?)`, now(), agentID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return agentID, nil
}

// ---- upload requests ----

// CreateUploadRequest mints a one-time human upload page token.
func (s *Store) CreateUploadRequest(agentID, note string, ttl time.Duration) (UploadRequest, error) {
	u := UploadRequest{
		Token: NewLinkToken(), AgentID: agentID, Note: note,
		ExpiresAt: time.Now().Add(ttl).Unix(), CreatedAt: now(),
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return UploadRequest{}, err
	}
	defer tx.Rollback()
	var live int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM upload_requests
		WHERE agent_id=? AND used=0 AND expires_at>?`, agentID, now()).Scan(&live); err != nil {
		return UploadRequest{}, err
	}
	if live >= MaxUploadRequestsPerAgent {
		return UploadRequest{}, fmt.Errorf("%w: at most %d live upload requests per agent", ErrLimit, MaxUploadRequestsPerAgent)
	}
	_, err = tx.Exec(`INSERT INTO upload_requests(token,agent_id,note,used,expires_at,created_at) VALUES(?,?,?,0,?,?)`,
		u.Token, u.AgentID, u.Note, u.ExpiresAt, u.CreatedAt)
	if err != nil {
		return u, err
	}
	return u, tx.Commit()
}

// GetUploadRequest fetches a live (unused, unexpired) upload request.
func (s *Store) GetUploadRequest(token string) (UploadRequest, error) {
	var u UploadRequest
	var used int
	err := s.DB.QueryRow(`SELECT token,agent_id,note,used,expires_at,created_at FROM upload_requests WHERE token=?`, token).
		Scan(&u.Token, &u.AgentID, &u.Note, &used, &u.ExpiresAt, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.Used = used == 1
	if u.Used || u.ExpiresAt <= now() {
		return u, ErrNotFound
	}
	return u, nil
}

// UseUploadRequest consumes an upload request (single use). It reports
// whether this call won the race.
func (s *Store) UseUploadRequest(token string) (bool, error) {
	res, err := s.DB.Exec(`UPDATE upload_requests SET used=1 WHERE token=? AND used=0 AND expires_at>?`, token, now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// UseUploadRequestWithFile consumes a one-time request and creates its folder
// entry in one transaction. A foreign-key, blob, or file insert failure rolls
// the token update back, so a retryable storage failure cannot burn the page.
func (s *Store) UseUploadRequestWithFile(token, agentID, sha, name, mime string, size int64, expiresAt int64) (File, bool, error) {
	f := File{
		ID: NewID("fil"), AgentID: agentID, SHA256: sha, Name: safeName(name), MIME: mime,
		Size: size, Source: "request", Claimed: false, ExpiresAt: expiresAt, CreatedAt: now(),
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return File{}, false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE upload_requests SET used=1
		WHERE token=? AND agent_id=? AND used=0 AND expires_at>?`, token, agentID, now())
	if err != nil {
		return File{}, false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return File{}, false, nil
	}
	if _, err := tx.Exec(`INSERT INTO files(id,agent_id,sha256,name,mime,size,source,claimed,expires_at,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(agent_id,name,sha256) DO UPDATE SET
			expires_at=CASE WHEN files.claimed=1 THEN files.expires_at ELSE excluded.expires_at END`,
		f.ID, f.AgentID, f.SHA256, f.Name, f.MIME, f.Size, f.Source, 0, f.ExpiresAt, f.CreatedAt); err != nil {
		return File{}, false, err
	}
	f, err = scanFile(tx.QueryRow(`SELECT `+fileCols+` FROM files
		WHERE agent_id=? AND name=? AND sha256=?`, agentID, f.Name, sha))
	if err != nil {
		return File{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return File{}, false, err
	}
	return f, true, nil
}

// ---- daily counters (rate limits) ----
//
// Counters key on (agent_id, day, kind); "agent_id" is any string identity,
// so the same table meters per-agent rate limits and connect host per-instance
// send/egress budgets.

// IncrCounter bumps and returns today's counter of a kind for an agent.
func (s *Store) IncrCounter(agentID, kind string) (int64, error) {
	return s.IncrCounterN(agentID, kind, 1)
}

// IncrCounterN bumps today's counter by n and returns the new total. n=0
// reads the current value; a negative n refunds a charge.
func (s *Store) IncrCounterN(agentID, kind string, n int64) (int64, error) {
	day := time.Now().UTC().Format("2006-01-02")
	if _, err := s.DB.Exec(`INSERT INTO counters(agent_id,day,kind,n) VALUES(?,?,?,?)
		ON CONFLICT(agent_id,day,kind) DO UPDATE SET n=n+excluded.n`, agentID, day, kind, n); err != nil {
		return 0, err
	}
	var v int64
	err := s.DB.QueryRow(`SELECT n FROM counters WHERE agent_id=? AND day=? AND kind=?`, agentID, day, kind).Scan(&v)
	return v, err
}

// ---- housekeeping ----

// Prune clears expired idempotency keys, verify tokens, upload requests and
// stale counters.
func (s *Store) Prune() error {
	cutoff := now() - 24*3600
	if _, err := s.DB.Exec(`DELETE FROM idempotency WHERE created_at<?`, cutoff); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM verify_tokens WHERE created_at<?`, now()-48*3600); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM upload_requests WHERE expires_at<? OR used=1`, now()-24*3600); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM links WHERE status<>'active' AND
		((status='expired' AND expires_at<?) OR (status<>'expired' AND created_at<?))`,
		now()-7*24*3600, now()-7*24*3600); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`DELETE FROM messages WHERE
		(read=1 AND received_at<?) OR (quarantined=1 AND received_at<?)`,
		now()-30*24*3600, now()-14*24*3600); err != nil {
		return err
	}
	day := time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02")
	_, err := s.DB.Exec(`DELETE FROM counters WHERE day<?`, day)
	return err
}
