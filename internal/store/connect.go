package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Connect persistence: the connect HOST keeps a registry of tunneled
// instances and a store-and-forward mail queue for the ones that are
// offline. The connect CLIENT persists its registration (host URL, name,
// token, public URL) via GetSetting/SetSetting.

const schemaConnect = `
CREATE TABLE IF NOT EXISTS connect_instances (
  name TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  owner_email TEXT NOT NULL DEFAULT '',
  verified INTEGER NOT NULL DEFAULT 0,
  suspended INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connect_mail (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  rcpts TEXT NOT NULL DEFAULT '[]',
  raw BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connect_mail_name ON connect_mail(name, created_at);
`

// ConnectInstance is one tunneled instance in the host registry. Only the
// fields the server actually reads are surfaced; created_at / last_seen /
// owner_email live in the table and are used by reaping and verification via
// SQL, not through this struct.
type ConnectInstance struct {
	Name      string
	Verified  bool
	Suspended bool
}

// GetSetting returns a persisted setting ("" if unset).
func (s *Store) GetSetting(k string) (string, error) { return s.getSetting(k) }

// SetSetting persists a setting.
func (s *Store) SetSetting(k, v string) error { return s.setSetting(k, v) }

// RenameInstance changes the instance domain and rewrites agent addresses to
// the new domain (agent emails are stored denormalized at creation time).
// Historical receipts keep the addresses that were true when they were
// signed — rewriting them would break the chain.
func (s *Store) RenameInstance(domain string) error {
	if domain == "" {
		return nil
	}
	s.instanceMu.Lock()
	defer s.instanceMu.Unlock()
	if domain == s.instance {
		return nil // nothing to change
	}
	if _, err := s.DB.Exec(`UPDATE agents SET email = name || '@' || ?`, domain); err != nil {
		return err
	}
	s.instance = domain
	return nil
}

// CreateConnectInstance registers a tunneled instance and returns its
// plaintext token (stored hashed).
func (s *Store) CreateConnectInstance(name string) (string, error) {
	token := "at_conn_" + randToken(32)
	_, err := s.DB.Exec(`INSERT INTO connect_instances(name,token_hash,created_at) VALUES(?,?,?)`,
		name, hashToken(token), now())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("name %q is taken", name)
		}
		return "", err
	}
	return token, nil
}

func scanConnectInstance(row interface{ Scan(...any) error }) (ConnectInstance, error) {
	var ci ConnectInstance
	var verified, suspended int
	err := row.Scan(&ci.Name, &verified, &suspended)
	if errors.Is(err, sql.ErrNoRows) {
		return ci, ErrNotFound
	}
	ci.Verified = verified == 1
	ci.Suspended = suspended == 1
	return ci, err
}

const connectCols = `name,verified,suspended`

// ConnectInstanceByName fetches a registered instance.
func (s *Store) ConnectInstanceByName(name string) (ConnectInstance, error) {
	return scanConnectInstance(s.DB.QueryRow(`SELECT `+connectCols+` FROM connect_instances WHERE name=?`, name))
}

// ConnectInstanceByToken resolves an instance token.
func (s *Store) ConnectInstanceByToken(token string) (ConnectInstance, error) {
	return scanConnectInstance(s.DB.QueryRow(`SELECT `+connectCols+` FROM connect_instances WHERE token_hash=?`, hashToken(token)))
}

// TouchConnectInstance records tunnel activity.
func (s *Store) TouchConnectInstance(name string) error {
	res, err := s.DB.Exec(`UPDATE connect_instances SET last_seen=? WHERE name=?`, now(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetConnectVerified marks an instance's owner verified (unlocks outbound
// email through the host).
func (s *Store) SetConnectVerified(name, ownerEmail string) error {
	res, err := s.DB.Exec(`UPDATE connect_instances SET verified=1, owner_email=? WHERE name=?`, ownerEmail, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetConnectSuspended flips the kill switch for an instance.
func (s *Store) SetConnectSuspended(name string, v bool) error {
	res, err := s.DB.Exec(`UPDATE connect_instances SET suspended=? WHERE name=?`, boolInt(v), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReapConnectInstances removes registrations that never connected within
// graceNew, or have been idle longer than graceIdle, along with their queued
// mail. Returns the reaped names.
func (s *Store) ReapConnectInstances(graceNew, graceIdle time.Duration) ([]string, error) {
	n := now()
	newCutoff, idleCutoff := n-int64(graceNew.Seconds()), n-int64(graceIdle.Seconds())
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT name FROM connect_instances
		WHERE (last_seen=0 AND created_at<=?) OR (last_seen>0 AND last_seen<=?)`,
		newCutoff, idleCutoff)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	reaped := names[:0]
	for _, name := range names {
		// Recheck the cutoff in the DELETE so a heartbeat that committed before
		// this transaction cannot lose its registration to the earlier scan.
		res, err := tx.Exec(`DELETE FROM connect_instances WHERE name=? AND
			((last_seen=0 AND created_at<=?) OR (last_seen>0 AND last_seen<=?))`,
			name, newCutoff, idleCutoff)
		if err != nil {
			return reaped, err
		}
		if changed, _ := res.RowsAffected(); changed != 1 {
			continue
		}
		if _, err := tx.Exec(`DELETE FROM connect_mail WHERE name=?`, name); err != nil {
			return reaped, err
		}
		reaped = append(reaped, name)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return reaped, nil
}

// ConnectMail is one queued inbound email for a tunneled instance.
type ConnectMail struct {
	ID    string
	Name  string
	Rcpts []string
	Raw   []byte
}

// ErrQueueFull is returned when an instance's mail queue is at capacity, so
// the SMTP path can answer a retryable 452 rather than a permanent reject.
var ErrQueueFull = errors.New("mail queue full")

// EnqueueConnectMail stores one inbound email for an instance, enforcing
// per-instance count and byte caps.
func (s *Store) EnqueueConnectMail(name string, rcpts []string, raw []byte, maxMsgs, maxBytes int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(`SELECT 1 FROM connect_instances WHERE name=?`, name).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var msgs, bytes sql.NullInt64
	if err := tx.QueryRow(`SELECT COUNT(*), SUM(LENGTH(raw)) FROM connect_mail WHERE name=?`, name).Scan(&msgs, &bytes); err != nil {
		return err
	}
	if msgs.Int64 >= maxMsgs || bytes.Int64+int64(len(raw)) > maxBytes {
		return ErrQueueFull
	}
	rcptsJSON, _ := json.Marshal(rcpts)
	_, err = tx.Exec(`INSERT INTO connect_mail(id,name,rcpts,raw,created_at) VALUES(?,?,?,?,?)`,
		NewID("cxm"), name, string(rcptsJSON), raw, now())
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ListConnectMail returns queued mail for an instance, oldest first.
func (s *Store) ListConnectMail(name string, limit int) ([]ConnectMail, error) {
	q := `SELECT id,name,rcpts,raw FROM connect_mail WHERE name=? ORDER BY created_at, id`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.DB.Query(q, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectMail
	for rows.Next() {
		var m ConnectMail
		var rcpts string
		if err := rows.Scan(&m.ID, &m.Name, &rcpts, &m.Raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(rcpts), &m.Rcpts)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteConnectMail acknowledges (removes) one queued message.
func (s *Store) DeleteConnectMail(name, id string) error {
	res, err := s.DB.Exec(`DELETE FROM connect_mail WHERE name=? AND id=?`, name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
