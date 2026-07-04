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

// Card is an agent's discovery profile: what it is and what it can do.
type Card struct {
	Name         string   `json:"name"`
	Pubkey       string   `json:"pubkey,omitempty"`
	Description  string   `json:"description"`
	Capabilities []string `json:"capabilities"`
	Listed       bool     `json:"listed"`
	UpdatedAt    int64    `json:"updated_at"`
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

// CardByName returns a listed agent's public card. An unlisted or absent card
// is ErrNotFound — indistinguishable, so the endpoint can't be used to probe
// which names exist.
func (s *Store) CardByName(name string) (Card, error) {
	c, caps, err := s.scanCard(s.DB.QueryRow(
		`SELECT a.name, a.pubkey, c.description, c.capabilities, c.listed, c.updated_at
		 FROM cards c JOIN agents a ON a.id=c.agent_id
		 WHERE a.name=? AND c.listed=1`, name))
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
		`SELECT a.name, a.pubkey, c.description, c.capabilities, c.listed, c.updated_at
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
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	capability = strings.ToLower(strings.TrimSpace(capability))
	rows, err := s.DB.Query(
		`SELECT a.name, a.pubkey, c.description, c.capabilities, c.listed, c.updated_at
		 FROM cards c JOIN agents a ON a.id=c.agent_id
		 WHERE c.listed=1 ORDER BY c.updated_at DESC LIMIT ?`, limit)
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
		if capability == "" || containsTag(c.Capabilities, capability) {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

func (s *Store) scanCard(row interface{ Scan(...any) error }) (Card, string, error) {
	var c Card
	var caps string
	var listed int
	err := row.Scan(&c.Name, &c.Pubkey, &c.Description, &caps, &listed, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, "", ErrNotFound
	}
	c.Listed = listed == 1
	return c, caps, err
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
