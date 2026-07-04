package store

import (
	"database/sql"
	"errors"
)

// schemaSpaces (migration 3) adds Spaces: a shared coordination context that
// multiple agents join — shared membership plus one shared event stream
// (messages and file offers). Members, spaces, and events are agent/space
// children with ON DELETE CASCADE, so deleting an agent or a space reaps its
// membership and stream with it. The global autoincrement space_events.seq is
// the long-poll / since cursor.
const schemaSpaces = `
CREATE TABLE IF NOT EXISTS spaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS space_members (
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (space_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_space_members_agent ON space_members(agent_id);

CREATE TABLE IF NOT EXISTS space_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  actor TEXT NOT NULL,
  kind TEXT NOT NULL,
  text TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  mime TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_space_events_space ON space_events(space_id, seq);
`

// Space is a shared coordination context that agents join.
type Space struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	OwnerID   string `json:"owner_id"`
	CreatedAt int64  `json:"created_at"`
}

// SpaceMember is one membership row, with the agent's name resolved by joining
// agents.
type SpaceMember struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	JoinedAt int64  `json:"joined_at"`
}

// SpaceEvent is one entry in a space's shared stream. kind is one of
// "message", "file", "join", "leave"; the file fields (sha256/name/mime/size)
// are set only on "file" events, text carries a message body or a file caption.
type SpaceEvent struct {
	Seq       int64  `json:"seq"`
	ID        string `json:"id"`
	SpaceID   string `json:"space_id"`
	Actor     string `json:"actor"`
	Kind      string `json:"kind"`
	Text      string `json:"text,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Name      string `json:"name,omitempty"`
	MIME      string `json:"mime,omitempty"`
	Size      int64  `json:"size,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

const spaceCols = `id,name,owner_id,created_at`

func scanSpace(row interface{ Scan(...any) error }) (Space, error) {
	var sp Space
	err := row.Scan(&sp.ID, &sp.Name, &sp.OwnerID, &sp.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return sp, ErrNotFound
	}
	return sp, err
}

// CreateSpace mints a space and enrolls its owner as the first member (role
// 'owner') in one transaction — a space without its owner would be an orphan.
func (s *Store) CreateSpace(ownerID, name string) (Space, error) {
	sp := Space{ID: NewID("spc"), Name: name, OwnerID: ownerID, CreatedAt: now()}
	tx, err := s.DB.Begin()
	if err != nil {
		return Space{}, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO spaces(id,name,owner_id,created_at) VALUES(?,?,?,?)`,
		sp.ID, sp.Name, sp.OwnerID, sp.CreatedAt); err != nil {
		return Space{}, err
	}
	if _, err := tx.Exec(`INSERT INTO space_members(space_id,agent_id,role,joined_at) VALUES(?,?,'owner',?)`,
		sp.ID, ownerID, sp.CreatedAt); err != nil {
		return Space{}, err
	}
	if err := tx.Commit(); err != nil {
		return Space{}, err
	}
	return sp, nil
}

// SpaceByID fetches a space by id; ErrNotFound if absent.
func (s *Store) SpaceByID(id string) (Space, error) {
	return scanSpace(s.DB.QueryRow(`SELECT `+spaceCols+` FROM spaces WHERE id=?`, id))
}

// SpaceMemberRole returns the agent's role in the space and whether it is a
// member at all — the membership gate every space-scoped handler consults.
func (s *Store) SpaceMemberRole(spaceID, agentID string) (string, bool) {
	var role string
	err := s.DB.QueryRow(`SELECT role FROM space_members WHERE space_id=? AND agent_id=?`, spaceID, agentID).Scan(&role)
	if err != nil {
		return "", false
	}
	return role, true
}

// AddSpaceMember enrolls an agent in a space. It is idempotent: re-adding an
// existing member is a no-op that keeps the current role and join time.
func (s *Store) AddSpaceMember(spaceID, agentID, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.DB.Exec(`INSERT INTO space_members(space_id,agent_id,role,joined_at) VALUES(?,?,?,?)
		ON CONFLICT(space_id,agent_id) DO NOTHING`, spaceID, agentID, role, now())
	return err
}

// RemoveSpaceMember drops an agent's membership; ErrNotFound if it wasn't a
// member.
func (s *Store) RemoveSpaceMember(spaceID, agentID string) error {
	res, err := s.DB.Exec(`DELETE FROM space_members WHERE space_id=? AND agent_id=?`, spaceID, agentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSpaceMembers returns a space's members (name resolved from agents),
// ordered by join time.
func (s *Store) ListSpaceMembers(spaceID string) ([]SpaceMember, error) {
	rows, err := s.DB.Query(`SELECT a.name, m.role, m.joined_at
		FROM space_members m JOIN agents a ON a.id=m.agent_id
		WHERE m.space_id=? ORDER BY m.joined_at, a.name`, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SpaceMember{}
	for rows.Next() {
		var m SpaceMember
		if err := rows.Scan(&m.Name, &m.Role, &m.JoinedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListSpacesForAgent returns the spaces an agent belongs to, newest first.
func (s *Store) ListSpacesForAgent(agentID string) ([]Space, error) {
	rows, err := s.DB.Query(`SELECT sp.id, sp.name, sp.owner_id, sp.created_at
		FROM spaces sp JOIN space_members m ON m.space_id=sp.id
		WHERE m.agent_id=? ORDER BY sp.created_at DESC, sp.id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Space{}
	for rows.Next() {
		sp, err := scanSpace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

const spaceEventCols = `seq,id,space_id,actor,kind,text,sha256,name,mime,size,created_at`

func scanSpaceEvent(row interface{ Scan(...any) error }) (SpaceEvent, error) {
	var ev SpaceEvent
	err := row.Scan(&ev.Seq, &ev.ID, &ev.SpaceID, &ev.Actor, &ev.Kind, &ev.Text,
		&ev.SHA256, &ev.Name, &ev.MIME, &ev.Size, &ev.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ev, ErrNotFound
	}
	return ev, err
}

// AddSpaceEvent appends one event to a space's stream and returns it with the
// assigned autoincrement seq (the since cursor).
func (s *Store) AddSpaceEvent(spaceID, actor, kind, text, sha, name, mime string, size int64) (SpaceEvent, error) {
	ev := SpaceEvent{
		ID: NewID("evt"), SpaceID: spaceID, Actor: actor, Kind: kind,
		Text: text, SHA256: sha, Name: name, MIME: mime, Size: size, CreatedAt: now(),
	}
	res, err := s.DB.Exec(`INSERT INTO space_events(id,space_id,actor,kind,text,sha256,name,mime,size,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.SpaceID, ev.Actor, ev.Kind, ev.Text, ev.SHA256, ev.Name, ev.MIME, ev.Size, ev.CreatedAt)
	if err != nil {
		return SpaceEvent{}, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return SpaceEvent{}, err
	}
	ev.Seq = seq
	return ev, nil
}

// ListSpaceEvents returns a space's events with seq strictly greater than
// sinceSeq, ascending. limit defaults to 200 and is capped at 500.
func (s *Store) ListSpaceEvents(spaceID string, sinceSeq int64, limit int) ([]SpaceEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.DB.Query(`SELECT `+spaceEventCols+` FROM space_events
		WHERE space_id=? AND seq>? ORDER BY seq LIMIT ?`, spaceID, sinceSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SpaceEvent{}
	for rows.Next() {
		ev, err := scanSpaceEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// MaxSpaceEventSeq returns the highest event seq in a space (0 when empty) —
// the cheap check a long-poll waiter loops on.
func (s *Store) MaxSpaceEventSeq(spaceID string) (int64, error) {
	var n sql.NullInt64
	err := s.DB.QueryRow(`SELECT MAX(seq) FROM space_events WHERE space_id=?`, spaceID).Scan(&n)
	return n.Int64, err
}

// SpaceFileEvent returns the most recent "file" event in the space carrying
// this sha256 — the proof that the blob was actually shared here, so
// membership alone can't pull an arbitrary blob. ErrNotFound if none.
func (s *Store) SpaceFileEvent(spaceID, sha string) (SpaceEvent, error) {
	return scanSpaceEvent(s.DB.QueryRow(`SELECT `+spaceEventCols+` FROM space_events
		WHERE space_id=? AND kind='file' AND sha256=? ORDER BY seq DESC LIMIT 1`, spaceID, sha))
}
