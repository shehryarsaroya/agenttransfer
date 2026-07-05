package store

import "time"

// PublicStats are the instance-level counters shown on the landing page.
// They are aggregate counts only — no names, no sizes, no content.
type PublicStats struct {
	Agents      int64 `json:"agents"`
	Transfers7d int64 `json:"transfers_7d"`
	Receipts    int64 `json:"receipts"`
}

// PublicStats counts agents, sends over the last 7 days, and the receipt
// chain length. Receipt timestamps are RFC3339 in UTC, so the cutoff
// comparison is a plain string compare.
func (s *Store) PublicStats() (PublicStats, error) {
	var st PublicStats
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&st.Agents); err != nil {
		return st, err
	}
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM receipts WHERE action='sent' AND ts>=?`, cutoff).Scan(&st.Transfers7d); err != nil {
		return st, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM receipts`).Scan(&st.Receipts); err != nil {
		return st, err
	}
	return st, nil
}
