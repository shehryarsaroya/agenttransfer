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
// the store's single write connection makes the check-then-insert atomic.
func (s *Store) CreatePerson(handle, email string) (Person, error) {
	handle = strings.ToLower(strings.TrimSpace(handle))
	email = strings.ToLower(strings.TrimSpace(email))
	if !validAgentName(handle) || strings.Contains(handle, "+") {
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
	tag = strings.ToLower(strings.TrimSpace(tag))
	if !validAgentName(tag) || strings.Contains(tag, "+") {
		return Agent{}, "", errors.New("invalid agent name: use 3-64 chars of a-z 0-9 . _ -")
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
	_, err := s.DB.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,person_id,created_at) VALUES(?,?,?,?,?,0,?,?)`,
		a.ID, a.Name, a.Email, hashToken(key), a.OwnerEmail, a.PersonID, a.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Agent{}, "", fmt.Errorf("agent name %q is taken: %w", name, ErrNameTaken)
		}
		return Agent{}, "", err
	}
	return a, key, nil
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
	rows, err := s.DB.Query(`SELECT `+personCols+` FROM persons
		WHERE verified_at=0 AND created_at < ?
		AND NOT EXISTS (SELECT 1 FROM agents WHERE person_id=persons.id AND owner_verified=1)`,
		now()-ttlSeconds)
	if err != nil {
		return 0, err
	}
	var stale []Person
	for rows.Next() {
		p, err := scanPerson(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		stale = append(stale, p)
	}
	rows.Close()
	released := 0
	for _, p := range stale {
		agents, err := s.AgentsByPerson(p.ID, false)
		if err != nil {
			return released, err
		}
		ok := true
		for _, a := range agents {
			if _, _, err := s.DeleteAgent(a.ID); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if _, err := s.DB.Exec(`DELETE FROM persons WHERE id=? AND verified_at=0`, p.ID); err == nil {
			released++
		}
	}
	return released, nil
}
