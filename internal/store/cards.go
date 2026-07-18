package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// schemaCards (migration 2) adds opt-in discovery cards. A card is absent for
// most agents; listed=1 is an explicit opt-in to appear in the directory, so
// the anti-enumeration default (unlisted agents are invisible) is preserved.
const schemaCards = `
CREATE TABLE IF NOT EXISTS cards (
  agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  description TEXT NOT NULL DEFAULT '',
  capabilities TEXT NOT NULL DEFAULT '[]',
  listed INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cards_listed ON cards(listed) WHERE listed=1;
`

// schemaIdentityV5 (migration 5) adds the opt-in public contact for the visible
// identity layer. owner_email stays private; public_contact is what an agent
// chooses to show (an address, URL, or handle).
const schemaIdentityV5 = `ALTER TABLE agents ADD COLUMN public_contact TEXT NOT NULL DEFAULT '';`

// Card is an agent's discovery profile: what it is and what it can do.
type Card struct {
	Name         string   `json:"name"`
	Pubkey       string   `json:"pubkey,omitempty"`
	Description  string   `json:"description"`
	Capabilities []string `json:"capabilities"`
	Listed       bool     `json:"listed"`
	UpdatedAt    int64    `json:"updated_at"`
	// PublicContact is an address/URL/handle the agent chose to publish (opt-in);
	// its private owner_email is never exposed here.
	PublicContact string `json:"public_contact,omitempty"`
	// OwnerVerified is carried for the server to compute the visible identity
	// tier; it is not itself serialized.
	OwnerVerified bool `json:"-"`
	// Verified is the computed identity tier ({tier, instance, basis}),
	// filled in by the server layer (which knows the instance config) before the
	// card is returned. The store leaves it nil.
	Verified any `json:"verified,omitempty"`
}

// SetCard upserts the agent's discovery card. capabilities are normalized to
// lowercase tags; listed=false keeps the agent out of the directory.
func (s *Store) SetCard(agentID, description string, capabilities []string, listed bool) error {
	tags := make([]string, 0, len(capabilities))
	seen := map[string]bool{}
	for _, c := range capabilities {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && !seen[c] {
			seen[c] = true
			tags = append(tags, c)
		}
	}
	caps, _ := json.Marshal(tags)
	_, err := s.DB.Exec(`INSERT INTO cards(agent_id,description,capabilities,listed,updated_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET
		  description=excluded.description, capabilities=excluded.capabilities,
		  listed=excluded.listed, updated_at=excluded.updated_at`,
		agentID, strings.TrimSpace(description), string(caps), boolInt(listed), now())
	return err
}

// SetPublicContact sets the agent's opt-in public contact ("" clears it).
func (s *Store) SetPublicContact(agentID, contact string) error {
	res, err := s.DB.Exec(`UPDATE agents SET public_contact=? WHERE id=?`, strings.TrimSpace(contact), agentID)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return nil
}

// CardByName returns a listed agent's public card. An unlisted or absent card
// is ErrNotFound — indistinguishable, so the endpoint can't be used to probe
// which names exist.
func (s *Store) CardByName(name string) (Card, error) {
	c, caps, err := s.scanCard(s.DB.QueryRow(
		`SELECT a.name, a.pubkey, a.owner_verified, a.public_contact, c.description, c.capabilities, c.listed, c.updated_at
		 FROM cards c JOIN agents a ON a.id=c.agent_id
		 WHERE a.name=? AND c.listed=1
		   AND NOT (a.person_id<>'' AND a.owner_verified=0)`, name))
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(caps), &c.Capabilities)
	return c, nil
}

// CardOf returns the agent's own card (whether listed or not); ErrNotFound if
// it hasn't set one.
func (s *Store) CardOf(agentID string) (Card, error) {
	c, caps, err := s.scanCard(s.DB.QueryRow(
		`SELECT a.name, a.pubkey, a.owner_verified, a.public_contact, c.description, c.capabilities, c.listed, c.updated_at
		 FROM cards c JOIN agents a ON a.id=c.agent_id WHERE c.agent_id=?`, agentID))
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(caps), &c.Capabilities)
	return c, nil
}

// Directory lists agents that opted into discovery, most-recently-updated first,
// optionally filtered to those advertising a capability tag.
func (s *Store) Directory(capability string, limit int) ([]Card, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	capability = strings.ToLower(strings.TrimSpace(capability))
	rows, err := s.DB.Query(
		`SELECT a.name, a.pubkey, a.owner_verified, a.public_contact, c.description, c.capabilities, c.listed, c.updated_at
		 FROM cards c JOIN agents a ON a.id=c.agent_id
		 WHERE c.listed=1
		   AND NOT (a.person_id<>'' AND a.owner_verified=0)
		   AND (?='' OR EXISTS (
		     SELECT 1 FROM json_each(c.capabilities) tag WHERE tag.value=?
		   ))
		 ORDER BY c.updated_at DESC LIMIT ?`, capability, capability, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Card
	for rows.Next() {
		c, caps, err := s.scanCard(rows)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(caps), &c.Capabilities)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) scanCard(row interface{ Scan(...any) error }) (Card, string, error) {
	var c Card
	var caps string
	var listed, ownerVerified int
	err := row.Scan(&c.Name, &c.Pubkey, &ownerVerified, &c.PublicContact, &c.Description, &caps, &listed, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, "", ErrNotFound
	}
	c.Listed = listed == 1
	c.OwnerVerified = ownerVerified == 1
	return c, caps, err
}
