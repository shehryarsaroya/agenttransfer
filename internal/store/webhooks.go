package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Webhooks: an agent registers an HTTPS URL to be POSTed when a message
// arrives, as a push alternative to long-polling the inbox. Deliveries are
// queued in a table and driven by a background worker (see server/webhooks.go)
// so a slow or dead endpoint never blocks the request that triggered it.

const schemaWebhooks = `
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  event_types TEXT NOT NULL DEFAULT '*',
  enabled INTEGER NOT NULL DEFAULT 1,
  fail_count INTEGER NOT NULL DEFAULT 0,
  disabled_reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  UNIQUE(agent_id, url)
);
CREATE INDEX IF NOT EXISTS idx_webhooks_agent ON webhooks(agent_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_status_code INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliv_due ON webhook_deliveries(status, next_attempt_at);
`

// Webhook is one registered push endpoint.
type Webhook struct {
	ID             string `json:"id"`
	AgentID        string `json:"-"`
	URL            string `json:"url"`
	Secret         string `json:"-"` // never serialized to clients after creation
	EventTypes     string `json:"event_types"`
	Enabled        bool   `json:"enabled"`
	FailCount      int64  `json:"fail_count"`
	DisabledReason string `json:"disabled_reason,omitempty"`
	CreatedAt      int64  `json:"created_at"`
}

// WebhookDelivery is one queued/attempted POST.
type WebhookDelivery struct {
	ID        string
	WebhookID string
	URL       string
	Secret    string
	EventType string
	Payload   []byte
	Attempts  int64
}

// MaxWebhooksPerAgent caps registrations so one agent can't fan out to many
// endpoints.
const MaxWebhooksPerAgent = 5

// CreateWebhook registers an endpoint, enforcing the per-agent cap. secret is
// stored as given (the plaintext signing secret); it is shown to the caller
// once and never returned again.
func (s *Store) CreateWebhook(agentID, url, secret, eventTypes string) (Webhook, error) {
	var n int64
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE agent_id=?`, agentID).Scan(&n); err != nil {
		return Webhook{}, err
	}
	if n >= MaxWebhooksPerAgent {
		return Webhook{}, fmt.Errorf("webhook limit reached (%d per agent)", MaxWebhooksPerAgent)
	}
	if eventTypes == "" {
		eventTypes = "*"
	}
	if len(eventTypes) > 256 {
		return Webhook{}, fmt.Errorf("event_types too long")
	}
	w := Webhook{
		ID: NewID("whk"), AgentID: agentID, URL: url, Secret: secret,
		EventTypes: eventTypes, Enabled: true, CreatedAt: now(),
	}
	_, err := s.DB.Exec(`INSERT INTO webhooks(id,agent_id,url,secret,event_types,enabled,created_at) VALUES(?,?,?,?,?,1,?)`,
		w.ID, w.AgentID, w.URL, w.Secret, w.EventTypes, w.CreatedAt)
	if err != nil {
		if isUniqueErr(err) {
			return Webhook{}, errors.New("a webhook for that URL already exists")
		}
		return Webhook{}, err
	}
	return w, nil
}

func scanWebhook(row interface{ Scan(...any) error }) (Webhook, error) {
	var w Webhook
	var enabled int
	err := row.Scan(&w.ID, &w.AgentID, &w.URL, &w.Secret, &w.EventTypes, &enabled, &w.FailCount, &w.DisabledReason, &w.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	w.Enabled = enabled == 1
	return w, err
}

const webhookCols = `id,agent_id,url,secret,event_types,enabled,fail_count,disabled_reason,created_at`

// ListWebhooks returns an agent's registered endpoints, newest first.
func (s *Store) ListWebhooks(agentID string) ([]Webhook, error) {
	rows, err := s.DB.Query(`SELECT `+webhookCols+` FROM webhooks WHERE agent_id=? ORDER BY created_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteWebhook removes an agent's endpoint (and cascades its deliveries).
func (s *Store) DeleteWebhook(agentID, id string) error {
	res, err := s.DB.Exec(`DELETE FROM webhooks WHERE agent_id=? AND id=?`, agentID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// FK ON DELETE CASCADE removes deliveries when foreign_keys is ON (it is).
	_, _ = s.DB.Exec(`DELETE FROM webhook_deliveries WHERE webhook_id=?`, id)
	return nil
}

// EnqueueDeliveries inserts a pending delivery for every ENABLED webhook of
// agentID subscribed to eventType. Matching is exact against the webhook's
// comma-separated event_types set ("*" = all) — NOT a substring LIKE, which
// would falsely match hierarchical names. payload is the exact bytes signed
// and sent. Best-effort per row; returns the first error.
func (s *Store) EnqueueDeliveries(agentID, eventType string, payload []byte) error {
	rows, err := s.DB.Query(`SELECT id, event_types FROM webhooks WHERE agent_id=? AND enabled=1`, agentID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, types string
		if err := rows.Scan(&id, &types); err != nil {
			rows.Close()
			return err
		}
		if eventTypeMatches(types, eventType) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	ts := now()
	for _, id := range ids {
		if _, err := s.DB.Exec(`INSERT INTO webhook_deliveries(id,webhook_id,event_type,payload,status,next_attempt_at,created_at,updated_at)
			VALUES(?,?,?,?, 'pending', ?, ?, ?)`, NewID("whd"), id, eventType, payload, ts, ts, ts); err != nil {
			return err
		}
	}
	return nil
}

// HasEnabledWebhooks reports whether the agent has any enabled endpoint — a
// cheap guard so the hot path skips building a payload when nobody's listening.
func (s *Store) HasEnabledWebhooks(agentID string) bool {
	var one int
	err := s.DB.QueryRow(`SELECT 1 FROM webhooks WHERE agent_id=? AND enabled=1 LIMIT 1`, agentID).Scan(&one)
	return err == nil
}

// ClaimDueDeliveries atomically marks up to limit due deliveries 'delivering'
// and returns them joined with their endpoint's url+secret. Skips deliveries
// whose webhook has since been disabled.
func (s *Store) ClaimDueDeliveries(limit int) ([]WebhookDelivery, error) {
	ts := now()
	rows, err := s.DB.Query(`SELECT d.id, d.webhook_id, w.url, w.secret, d.event_type, d.payload, d.attempts
		FROM webhook_deliveries d JOIN webhooks w ON w.id=d.webhook_id
		WHERE d.status='pending' AND d.next_attempt_at<=? AND w.enabled=1
		ORDER BY d.next_attempt_at LIMIT ?`, ts, limit)
	if err != nil {
		return nil, err
	}
	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.URL, &d.Secret, &d.EventType, &d.Payload, &d.Attempts); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	for _, d := range out {
		if _, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='delivering', updated_at=? WHERE id=?`, ts, d.ID); err != nil {
			return out, err
		}
	}
	return out, nil
}

// MarkDelivered records a successful delivery and clears the endpoint's
// consecutive-failure counter.
func (s *Store) MarkDelivered(deliveryID, webhookID string, statusCode int) error {
	ts := now()
	if _, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='succeeded', attempts=attempts+1, last_status_code=?, updated_at=? WHERE id=?`,
		statusCode, ts, deliveryID); err != nil {
		return err
	}
	_, err := s.DB.Exec(`UPDATE webhooks SET fail_count=0 WHERE id=?`, webhookID)
	return err
}

// RescheduleDelivery bumps attempts and sets the next retry time.
func (s *Store) RescheduleDelivery(deliveryID string, nextAt int64, statusCode int, errStr string) error {
	_, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='pending', attempts=attempts+1, next_attempt_at=?, last_status_code=?, last_error=?, updated_at=? WHERE id=?`,
		nextAt, statusCode, truncErr(errStr), now(), deliveryID)
	return err
}

// FailDeliveryDead marks a delivery permanently failed and bumps the
// endpoint's consecutive-failure counter, returning the new count so the
// caller can auto-disable past a threshold.
func (s *Store) FailDeliveryDead(deliveryID, webhookID string, statusCode int, errStr string) (int64, error) {
	ts := now()
	if _, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='dead', attempts=attempts+1, last_status_code=?, last_error=?, updated_at=? WHERE id=?`,
		statusCode, truncErr(errStr), ts, deliveryID); err != nil {
		return 0, err
	}
	if _, err := s.DB.Exec(`UPDATE webhooks SET fail_count=fail_count+1 WHERE id=?`, webhookID); err != nil {
		return 0, err
	}
	var n int64
	err := s.DB.QueryRow(`SELECT fail_count FROM webhooks WHERE id=?`, webhookID).Scan(&n)
	return n, err
}

// DisableWebhook turns an endpoint off with a reason (auto-disable after
// repeated failure, or operator action).
func (s *Store) DisableWebhook(webhookID, reason string) error {
	_, err := s.DB.Exec(`UPDATE webhooks SET enabled=0, disabled_reason=? WHERE id=?`, reason, webhookID)
	return err
}

// AgentIDForWebhook returns the owning agent, for out-of-band failure notices.
func (s *Store) AgentIDForWebhook(webhookID string) (string, error) {
	var id string
	err := s.DB.QueryRow(`SELECT agent_id FROM webhooks WHERE id=?`, webhookID).Scan(&id)
	return id, err
}

// ResetStaleDeliveries reclaims deliveries stuck 'delivering' from a prior
// crash back to 'pending' (run once at startup).
func (s *Store) ResetStaleDeliveries() error {
	_, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='pending' WHERE status='delivering'`)
	return err
}

// ReclaimStuckDeliveries resets 'delivering' rows not touched since cutoff back
// to 'pending'. A single attempt is bounded by the per-POST budget (~15s), so a
// row that's been 'delivering' for minutes means the terminal store write was
// lost (transient DB error); the janitor reclaims it rather than stranding it
// until the next process restart.
func (s *Store) ReclaimStuckDeliveries(cutoff int64) error {
	_, err := s.DB.Exec(`UPDATE webhook_deliveries SET status='pending' WHERE status='delivering' AND updated_at<?`, cutoff)
	return err
}

// PruneWebhookDeliveries drops terminal delivery rows older than cutoff.
func (s *Store) PruneWebhookDeliveries(cutoff int64) error {
	_, err := s.DB.Exec(`DELETE FROM webhook_deliveries WHERE status IN ('succeeded','dead') AND updated_at<?`, cutoff)
	return err
}

// eventTypeMatches reports whether a webhook's comma-separated event_types set
// subscribes to eventType. "*" matches everything; otherwise an exact token
// match (no substring surprises).
func eventTypeMatches(set, eventType string) bool {
	for _, t := range strings.Split(set, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || t == eventType {
			return true
		}
	}
	return false
}

func truncErr(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}
