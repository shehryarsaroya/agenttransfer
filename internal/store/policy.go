package store

import (
	"database/sql"
	"errors"
	"strings"
)

// schemaPolicy (migration 4) adds recipient-side accept policy + quarantine.
// Trust for agent-to-agent is decided by the RECEIVER: who reaches the main
// inbox vs a quarantine bucket, rather than gating the sender. (The separate
// email-projection circle cap is unrelated and stays.)
const schemaPolicy = `
ALTER TABLE agents ADD COLUMN accept_policy TEXT NOT NULL DEFAULT 'open';
ALTER TABLE messages ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS agent_allow (
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  addr TEXT NOT NULL,
  PRIMARY KEY (agent_id, addr)
);
`

// AcceptPolicies enumerates valid accept_policy values.
//
//	open   — everyone reaches the main inbox (default).
//	known  — allowlisted or space co-members reach the main inbox; others go to quarantine.
//	closed — known senders reach the main inbox; unknown senders are rejected outright.
var AcceptPolicies = map[string]bool{"open": true, "known": true, "closed": true}

// SetPolicy sets the agent's accept policy and replaces its allowlist atomically.
func (s *Store) SetPolicy(agentID, accept string, allow []string) error {
	if accept == "" {
		accept = "open"
	}
	if !AcceptPolicies[accept] {
		return errors.New("accept must be one of: open, known, closed")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE agents SET accept_policy=? WHERE id=?`, accept, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM agent_allow WHERE agent_id=?`, agentID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		if _, err := tx.Exec(`INSERT INTO agent_allow(agent_id,addr) VALUES(?,?)`, agentID, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Allowlist returns the agent's allowlisted sender addresses.
func (s *Store) Allowlist(agentID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT addr FROM agent_allow WHERE agent_id=? ORDER BY addr`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SenderKnown reports whether senderAddr is "known" to the recipient: either
// explicitly allowlisted, or a same-instance agent that shares a space with the
// recipient. This is the trust signal behind the "known"/"closed" policies —
// a sender you've vetted (allowlist) or already collaborate with (a space).
func (s *Store) SenderKnown(recipientID, senderAddr string) (bool, error) {
	senderAddr = strings.ToLower(strings.TrimSpace(senderAddr))
	if senderAddr == "" {
		return false, nil
	}
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM agent_allow WHERE agent_id=? AND addr=?`, recipientID, senderAddr).Scan(&one)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	// A same-instance sender co-present in any of the recipient's spaces is known.
	if localpart, domain, ok := strings.Cut(senderAddr, "@"); ok && domain == s.instance {
		err := s.DB.QueryRow(`SELECT 1 FROM space_members a
			JOIN space_members b ON a.space_id=b.space_id
			JOIN agents ag ON ag.id=b.agent_id
			WHERE a.agent_id=? AND ag.name=? LIMIT 1`, recipientID, localpart).Scan(&one)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return false, nil
}
