package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Persons make humans first-class: a person owns a handle (their address
// localpart), a verified email, and any number of agents. Person-owned agents
// live at handle+tag@instance — the plus-address IS the agent name, so every
// existing name-keyed path (auth, lookup, SMTP) works unchanged. Flat-named
// keyed agents (no person) are untouched: the anonymous tier stays anonymous.
//
// The trust rule: a person's handle and address grant NOTHING until the
// person's email is verified, and each additional agent must be approved by
// its own email click ("laptop wants to join your fleet"). Pending agents
// cannot receive at their plus-address — otherwise registering dana+evil
// would intercept mail meant for Dana's fleet.
const schemaPersonsV6 = `
CREATE TABLE IF NOT EXISTS persons (
  id TEXT PRIMARY KEY,
  handle TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  verified_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
ALTER TABLE agents ADD COLUMN person_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_agents_person ON agents(person_id) WHERE person_id <> '';
`

// schemaLocalNamesV11 makes the shared localpart namespace a database
// invariant. The original persons migration enforced it with cross-table
// check-then-insert code, which can interleave across goroutines even when the
// sql.DB has one connection. Backfill is intentionally strict: if an older
// database somehow contains a person/agent collision, the UNIQUE failure stops
// startup rather than silently choosing which identity owns the address.
const schemaLocalNamesV11 = `
CREATE TABLE local_names (
  name TEXT PRIMARY KEY COLLATE NOCASE,
  kind TEXT NOT NULL CHECK(kind IN ('agent','person')),
  ref_id TEXT NOT NULL UNIQUE
);
INSERT INTO local_names(name,kind,ref_id)
  SELECT name,'agent',id FROM agents;
INSERT INTO local_names(name,kind,ref_id)
  SELECT handle,'person',id FROM persons;

CREATE TRIGGER local_names_agent_insert
BEFORE INSERT ON agents
BEGIN
  INSERT INTO local_names(name,kind,ref_id) VALUES(NEW.name,'agent',NEW.id);
END;
CREATE TRIGGER local_names_agent_delete
AFTER DELETE ON agents
BEGIN
  DELETE FROM local_names WHERE kind='agent' AND ref_id=OLD.id;
END;
CREATE TRIGGER local_names_agent_name_immutable
BEFORE UPDATE OF name ON agents WHEN NEW.name<>OLD.name
BEGIN
  SELECT RAISE(ABORT,'agent names are immutable');
END;

CREATE TRIGGER local_names_person_insert
BEFORE INSERT ON persons
BEGIN
  INSERT INTO local_names(name,kind,ref_id) VALUES(NEW.handle,'person',NEW.id);
END;
CREATE TRIGGER local_names_person_delete
AFTER DELETE ON persons
BEGIN
  DELETE FROM local_names WHERE kind='person' AND ref_id=OLD.id;
END;
CREATE TRIGGER local_names_person_handle_immutable
BEFORE UPDATE OF handle ON persons WHEN NEW.handle<>OLD.handle
BEGIN
  SELECT RAISE(ABORT,'person handles are immutable');
END;
`

type Person struct {
	ID         string `json:"id"`
	Handle     string `json:"handle"`
	Email      string `json:"email"`
	VerifiedAt int64  `json:"verified_at"`
	CreatedAt  int64  `json:"created_at"`
}

func (p Person) Verified() bool { return p.VerifiedAt > 0 }

// ErrHandleTaken distinguishes handle collisions (persons or flat agents own
// the localpart) from other failures.
var ErrHandleTaken = errors.New("handle taken")

// CreatePerson claims a handle + email. The handle shares the address
// localpart namespace with flat agent names, so both tables are checked;
// local_names triggers make the final claim atomic with the insert.
func (s *Store) CreatePerson(handle, email string) (Person, error) {
	handle = strings.ToLower(strings.TrimSpace(handle))
	email = strings.ToLower(strings.TrimSpace(email))
	if !ValidAgentName(handle) || strings.Contains(handle, "+") {
		return Person{}, errors.New("invalid handle: use 3-64 chars of a-z 0-9 . _ -")
	}
	if email == "" {
		return Person{}, errors.New("a person needs an email")
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agents WHERE name=?`, handle).Scan(&n); err != nil {
		return Person{}, err
	}
	if n > 0 {
		return Person{}, fmt.Errorf("handle %q is taken by an agent: %w", handle, ErrHandleTaken)
	}
	p := Person{ID: NewID("prs"), Handle: handle, Email: email, CreatedAt: now()}
	_, err := s.DB.Exec(`INSERT INTO persons(id,handle,email,verified_at,created_at) VALUES(?,?,?,0,?)`,
		p.ID, p.Handle, p.Email, p.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Person{}, fmt.Errorf("handle or email already registered: %w", ErrHandleTaken)
		}
		return Person{}, err
	}
	return p, nil
}

func scanPerson(row interface{ Scan(...any) error }) (Person, error) {
	var p Person
	err := row.Scan(&p.ID, &p.Handle, &p.Email, &p.VerifiedAt, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

const personCols = `id,handle,email,verified_at,created_at`

func (s *Store) PersonByHandle(handle string) (Person, error) {
	return scanPerson(s.DB.QueryRow(`SELECT `+personCols+` FROM persons WHERE handle=?`, strings.ToLower(strings.TrimSpace(handle))))
}

func (s *Store) PersonByID(id string) (Person, error) {
	return scanPerson(s.DB.QueryRow(`SELECT `+personCols+` FROM persons WHERE id=?`, id))
}

// MarkPersonVerified is idempotent; the first approving click verifies the
// person along with the agent.
func (s *Store) MarkPersonVerified(id string) error {
	_, err := s.DB.Exec(`UPDATE persons SET verified_at=? WHERE id=? AND verified_at=0`, now(), id)
	return err
}

// CreateAgentForPerson mints handle+tag@instance. The agent starts attach-
// pending (owner_verified=0) even when the person is verified — each machine
// is approved by its own click. owner_email is denormalized from the person
// so every existing owner-keyed path (quota tier, outbound gate, CC, caps)
// works unchanged.
func (s *Store) CreateAgentForPerson(p Person, tag string) (Agent, string, error) {
	return s.CreateAgentForPersonLimited(p, tag, 0)
}

// CreateAgentForPersonLimited adds a pending machine to an existing person.
// maxAgents is intentionally unused: a machine consumes the person's mailbox
// cap only after its own email challenge succeeds.
func (s *Store) CreateAgentForPersonLimited(p Person, tag string, _ int64) (Agent, string, error) {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if !ValidAgentName(tag) || strings.Contains(tag, "+") {
		return Agent{}, "", errors.New("invalid agent name: use 3-64 chars of a-z 0-9 . _ -")
	}
	s.instanceMu.RLock()
	defer s.instanceMu.RUnlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return Agent{}, "", err
	}
	defer tx.Rollback()
	var email string
	if err := tx.QueryRow(`SELECT email FROM persons WHERE id=?`, p.ID).Scan(&email); errors.Is(err, sql.ErrNoRows) {
		return Agent{}, "", ErrNotFound
	} else if err != nil {
		return Agent{}, "", err
	}
	if !strings.EqualFold(email, p.Email) {
		return Agent{}, "", ErrNotFound
	}
	name := p.Handle + "+" + tag
	key := "at_live_" + randToken(32)
	a := Agent{
		ID:         NewID("agt"),
		Name:       name,
		Email:      name + "@" + s.instance,
		OwnerEmail: p.Email,
		PersonID:   p.ID,
		CreatedAt:  now(),
	}
	_, err = tx.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,
		person_id,owner_pending_at,created_at) VALUES(?,?,?,?,?,0,?,?,?)`,
		a.ID, a.Name, a.Email, hashToken(key), a.OwnerEmail, a.PersonID, a.CreatedAt, a.CreatedAt)
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

// CreatePersonWithAgent creates a new handle and its first machine as one
// indivisible unit. A validation, cap, namespace, or agent insert failure rolls
// back the person row too, so a failed signup cannot squat a handle or race a
// second create-or-join request into an orphaned person_id.
func (s *Store) CreatePersonWithAgent(handle, email, tag string, _ int64) (Person, Agent, string, error) {
	handle = strings.ToLower(strings.TrimSpace(handle))
	email = strings.ToLower(strings.TrimSpace(email))
	tag = strings.ToLower(strings.TrimSpace(tag))
	if !ValidAgentName(handle) || strings.Contains(handle, "+") {
		return Person{}, Agent{}, "", errors.New("invalid handle: use 3-64 chars of a-z 0-9 . _ -")
	}
	if email == "" {
		return Person{}, Agent{}, "", errors.New("a person needs an email")
	}
	if !ValidAgentName(tag) || strings.Contains(tag, "+") {
		return Person{}, Agent{}, "", errors.New("invalid agent name: use 3-64 chars of a-z 0-9 . _ -")
	}
	s.instanceMu.RLock()
	defer s.instanceMu.RUnlock()

	p := Person{ID: NewID("prs"), Handle: handle, Email: email, CreatedAt: now()}
	key := "at_live_" + randToken(32)
	a := Agent{
		ID: NewID("agt"), Name: handle + "+" + tag,
		Email:      handle + "+" + tag + "@" + s.instance,
		OwnerEmail: email, PersonID: p.ID, CreatedAt: now(),
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return Person{}, Agent{}, "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO persons(id,handle,email,verified_at,created_at) VALUES(?,?,?,0,?)`,
		p.ID, p.Handle, p.Email, p.CreatedAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Person{}, Agent{}, "", fmt.Errorf("handle or email already registered: %w", ErrHandleTaken)
		}
		return Person{}, Agent{}, "", err
	}
	if _, err := tx.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,
		person_id,owner_pending_at,created_at) VALUES(?,?,?,?,?,0,?,?,?)`,
		a.ID, a.Name, a.Email, hashToken(key), a.OwnerEmail, a.PersonID, a.CreatedAt, a.CreatedAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Person{}, Agent{}, "", fmt.Errorf("agent name %q is taken: %w", a.Name, ErrNameTaken)
		}
		return Person{}, Agent{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Person{}, Agent{}, "", err
	}
	return p, a, key, nil
}

// AgentsByPerson lists a person's agents. approvedOnly filters to agents
// whose join click happened — the only ones that receive at the person's
// address or their own plus-address.
func (s *Store) AgentsByPerson(personID string, approvedOnly bool) ([]Agent, error) {
	q := `SELECT ` + agentCols + ` FROM agents WHERE person_id=?`
	if approvedOnly {
		q += ` AND owner_verified=1`
	}
	q += ` ORDER BY created_at`
	rows, err := s.DB.Query(q, personID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SweepStalePendingPersons releases handles squatted by never-verified
// signups: a person still unverified after ttlSeconds, with no approved
// agents, is deleted along with its pending agents (scratchpad-tier data
// only; receipts remain, as always). Returns the number of persons released.
func (s *Store) SweepStalePendingPersons(ttlSeconds int64) (int, error) {
	cutoff := now() - ttlSeconds
	rows, err := s.DB.Query(`SELECT id FROM persons
		WHERE verified_at=0 AND created_at < ?
		AND NOT EXISTS (SELECT 1 FROM agents WHERE person_id=persons.id AND owner_verified=1)`, cutoff)
	if err != nil {
		return 0, err
	}
	var stale []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		stale = append(stale, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	released := 0
	for _, personID := range stale {
		// Recheck and delete inside one transaction. Verification either commits
		// first (and this becomes a no-op), or cleanup commits first (and the stale
		// token disappears with the agent); it can no longer delete an agent that
		// was verified between the initial scan and DeleteAgent.
		tx, err := s.DB.Begin()
		if err != nil {
			return released, err
		}
		var eligible int
		err = tx.QueryRow(`SELECT 1 FROM persons WHERE id=? AND verified_at=0 AND created_at<?
			AND NOT EXISTS (SELECT 1 FROM agents WHERE person_id=persons.id AND owner_verified=1)`,
			personID, cutoff).Scan(&eligible)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			continue
		}
		if err != nil {
			tx.Rollback()
			return released, err
		}
		queries := []string{
			`DELETE FROM counters WHERE agent_id IN (SELECT id FROM agents WHERE person_id=?)`,
			`DELETE FROM verify_tokens WHERE agent_id IN (SELECT id FROM agents WHERE person_id=?)`,
			`DELETE FROM agents WHERE person_id=? AND owner_verified=0`,
		}
		for _, q := range queries {
			if _, err := tx.Exec(q, personID); err != nil {
				tx.Rollback()
				return released, err
			}
		}
		res, err := tx.Exec(`DELETE FROM persons WHERE id=? AND verified_at=0
			AND NOT EXISTS (SELECT 1 FROM agents WHERE person_id=persons.id)`, personID)
		if err != nil {
			tx.Rollback()
			return released, err
		}
		deleted, _ := res.RowsAffected()
		if err := tx.Commit(); err != nil {
			return released, err
		}
		if deleted == 1 {
			released++
		}
	}
	return released, nil
}
