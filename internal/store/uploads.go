package store

import (
	"database/sql"
	"errors"
)

// schemaUploadSessionsV16 tracks direct-to-bucket uploads. A client asks for a
// session, PUTs bytes straight to object storage with presigned URLs (single
// request or resumable multipart), then calls complete; the server re-reads
// the object, hashes it, and only then records a blob and a folder entry. A
// session's size is charged against the folder's quota from creation, so
// parallel sessions cannot overshoot it.
const schemaUploadSessionsV16 = `
CREATE TABLE upload_sessions (
  id TEXT PRIMARY KEY,
  folder_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  declared_sha256 TEXT NOT NULL DEFAULT '',
  object_key TEXT NOT NULL,
  s3_upload_id TEXT NOT NULL DEFAULT '',
  part_size INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  error TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '',
  share INTEGER NOT NULL DEFAULT 0,
  ttl_seconds INTEGER NOT NULL DEFAULT 0,
  once INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_upload_sessions_folder ON upload_sessions(folder_id, status);
CREATE INDEX idx_upload_sessions_expiry ON upload_sessions(status, expires_at);
`

// Upload session states.
const (
	UploadPending   = "pending"
	UploadVerifying = "verifying"
	UploadDone      = "done"
	UploadFailed    = "failed"
	UploadExpired   = "expired"
)

// UploadSession is one direct-to-bucket upload.
type UploadSession struct {
	ID             string
	FolderID       string
	ActorID        string
	Name           string
	MIME           string
	Size           int64
	DeclaredSHA256 string
	ObjectKey      string
	S3UploadID     string
	PartSize       int64
	Status         string
	Error          string
	SHA256         string
	Share          bool
	TTLSeconds     int64
	Once           bool
	CreatedAt      int64
	ExpiresAt      int64
	CompletedAt    int64
}

// Multipart reports whether the session uploads in parts.
func (u UploadSession) Multipart() bool { return u.S3UploadID != "" }

// Parts is the number of parts a multipart session expects.
func (u UploadSession) Parts() int {
	if !u.Multipart() || u.PartSize <= 0 {
		return 1
	}
	return int((u.Size + u.PartSize - 1) / u.PartSize)
}

const uploadCols = `id,folder_id,actor_id,name,mime,size,declared_sha256,object_key,s3_upload_id,part_size,
	status,error,sha256,share,ttl_seconds,once,created_at,expires_at,completed_at`

func scanUpload(row interface{ Scan(...any) error }) (UploadSession, error) {
	var u UploadSession
	var share, once int
	err := row.Scan(&u.ID, &u.FolderID, &u.ActorID, &u.Name, &u.MIME, &u.Size, &u.DeclaredSHA256,
		&u.ObjectKey, &u.S3UploadID, &u.PartSize, &u.Status, &u.Error, &u.SHA256, &share,
		&u.TTLSeconds, &once, &u.CreatedAt, &u.ExpiresAt, &u.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Share = share == 1
	u.Once = once == 1
	return u, err
}

// CreateUploadSession records a new pending session. The caller has already
// checked quota (see PendingUploadBytes) under the folder's upload lock.
func (s *Store) CreateUploadSession(u UploadSession) (UploadSession, error) {
	if u.ID == "" {
		u.ID = NewID("upl")
	}
	if u.CreatedAt == 0 {
		u.CreatedAt = now()
	}
	u.Status = UploadPending
	_, err := s.DB.Exec(`INSERT INTO upload_sessions(`+uploadCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.FolderID, u.ActorID, u.Name, u.MIME, u.Size, u.DeclaredSHA256, u.ObjectKey, u.S3UploadID,
		u.PartSize, u.Status, u.Error, u.SHA256, boolInt(u.Share), u.TTLSeconds, boolInt(u.Once),
		u.CreatedAt, u.ExpiresAt, u.CompletedAt)
	return u, err
}

// GetUploadSession loads a session by id.
func (s *Store) GetUploadSession(id string) (UploadSession, error) {
	return scanUpload(s.DB.QueryRow(`SELECT `+uploadCols+` FROM upload_sessions WHERE id=?`, id))
}

// TransitionUpload moves a session from one status to another atomically and
// reports whether this caller won the transition.
func (s *Store) TransitionUpload(id, from, to, errMsg, sha string) (bool, error) {
	completed := int64(0)
	if to == UploadDone || to == UploadFailed || to == UploadExpired {
		completed = now()
	}
	res, err := s.DB.Exec(`UPDATE upload_sessions SET status=?, error=?,
		sha256=CASE WHEN ?<>'' THEN ? ELSE sha256 END,
		completed_at=CASE WHEN ?>0 THEN ? ELSE completed_at END
		WHERE id=? AND status=?`, to, errMsg, sha, sha, completed, completed, id, from)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// PendingUploadBytes sums the declared sizes of a folder's in-flight sessions;
// they count against quota until they finish or expire.
func (s *Store) PendingUploadBytes(folderID string) (int64, error) {
	var n sql.NullInt64
	err := s.DB.QueryRow(`SELECT SUM(size) FROM upload_sessions WHERE folder_id=?
		AND status IN ('pending','verifying')`, folderID).Scan(&n)
	return n.Int64, err
}

// CountActiveUploads counts a folder's in-flight sessions.
func (s *Store) CountActiveUploads(folderID string) (int64, error) {
	var n int64
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM upload_sessions WHERE folder_id=?
		AND status IN ('pending','verifying')`, folderID).Scan(&n)
	return n, err
}

// StaleUploadSessions returns pending sessions past their expiry, plus
// sessions stuck verifying for over an hour (a crash mid-verify).
func (s *Store) StaleUploadSessions(limit int) ([]UploadSession, error) {
	rows, err := s.DB.Query(`SELECT `+uploadCols+` FROM upload_sessions
		WHERE (status='pending' AND expires_at<?) OR (status='verifying' AND created_at<?)
		ORDER BY expires_at LIMIT ?`, now(), now()-3*3600, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UploadSession
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PruneUploadSessions drops finished session records older than a week.
func (s *Store) PruneUploadSessions() error {
	_, err := s.DB.Exec(`DELETE FROM upload_sessions WHERE status IN ('done','failed','expired') AND created_at<?`,
		now()-7*24*3600)
	return err
}
