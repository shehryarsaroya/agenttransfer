package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// schemaDriveV15 gives each verified person one shared drive. The drive is an
// agents row of kind 'drive' named handle+drive: files, links, quota and expiry
// already hang off an owning agent, so the drive reuses all of that machinery.
// A drive is never keyed, never addressable, and never listed as a member of
// the person's fleet; every approved agent of the person reads and writes it,
// and disconnecting one of those agents leaves the drive untouched.
const schemaDriveV15 = `
ALTER TABLE agents ADD COLUMN kind TEXT NOT NULL DEFAULT 'agent';
CREATE INDEX idx_agents_person_kind ON agents(person_id, kind) WHERE person_id <> '';
`

const (
	// KindAgent is an ordinary, keyed, addressable agent.
	KindAgent = "agent"
	// KindDrive is a person's shared drive (see schemaDriveV15).
	KindDrive = "drive"
	// DriveTag is the reserved plus-tag naming a person's drive.
	DriveTag = "drive"
)

// IsDrive reports whether a is a person's shared drive rather than an agent.
func (a Agent) IsDrive() bool { return a.Kind == KindDrive }

// reservedPersonTag reports plus-tags that person agents may not claim.
func reservedPersonTag(tag string) bool { return tag == DriveTag }

// DriveForPerson returns the person's drive, creating it on first use. Only a
// verified person has a drive: an unverified person's agents work in their own
// scratch folders until the person proves their mailbox.
func (s *Store) DriveForPerson(personID string) (Agent, error) {
	if a, err := scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents
		WHERE person_id=? AND kind='drive'`, personID)); err == nil {
		return a, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Agent{}, err
	}
	p, err := s.PersonByID(personID)
	if err != nil {
		return Agent{}, err
	}
	if !p.Verified() {
		return Agent{}, fmt.Errorf("person %s is not verified: %w", p.Handle, ErrNotFound)
	}
	s.instanceMu.RLock()
	defer s.instanceMu.RUnlock()
	name := p.Handle + "+" + DriveTag
	a := Agent{
		ID: NewID("drv"), Name: name, Email: name + "@" + s.instance,
		OwnerEmail: p.Email, OwnerVerified: true, OwnerVerifiedAt: now(),
		OwnerVerificationMethod: "email", PersonID: p.ID, Kind: KindDrive, CreatedAt: now(),
	}
	// The key hash is of a random secret that is never returned: no request can
	// ever authenticate as a drive.
	_, err = s.DB.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,
		owner_verified_at,owner_verification_method,person_id,kind,created_at)
		VALUES(?,?,?,?,?,1,?,?,?,'drive',?)`,
		a.ID, a.Name, a.Email, hashToken("drive_"+randToken(32)), a.OwnerEmail,
		a.OwnerVerifiedAt, a.OwnerVerificationMethod, a.PersonID, a.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			// Lost a creation race (or the name is somehow taken): re-read.
			return scanAgent(s.DB.QueryRow(`SELECT `+agentCols+` FROM agents
				WHERE person_id=? AND kind='drive'`, personID))
		}
		return Agent{}, err
	}
	return a, nil
}

// MergeFolderIntoDrive moves an agent's scratch folder and live links into
// its person's drive — run when the agent is approved, so nothing it saved
// while pending disappears. Name+content duplicates collapse into one entry.
func (s *Store) MergeFolderIntoDrive(agentID, driveID string) error {
	if agentID == driveID {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Move entries the drive doesn't already hold (claimed files become
	// persistent at the drive's verified tier); drop exact duplicates.
	if _, err := tx.Exec(`UPDATE files SET agent_id=?,
			expires_at=CASE WHEN claimed=1 THEN 0 ELSE expires_at END
		WHERE agent_id=? AND NOT EXISTS (SELECT 1 FROM files d
			WHERE d.agent_id=? AND d.name=files.name AND d.sha256=files.sha256)`,
		driveID, agentID, driveID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM files WHERE agent_id=?`, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE links SET agent_id=? WHERE agent_id=?`, driveID, agentID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeletePerson removes a person's account: every agent (drive included, with
// its files and links via cascade), sessions, OAuth grants, and the person row.
// Receipts are an append-only signed log and remain. Orphaned blobs are
// collected by the next GC run.
func (s *Store) DeletePerson(personID string) error {
	p, err := s.PersonByID(personID)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM oauth_grants WHERE person_id=?`,
		`DELETE FROM oauth_tokens WHERE person_id=?`,
		`DELETE FROM oauth_codes WHERE person_id=?`,
		`DELETE FROM web_sessions WHERE person_id=?`,
		`DELETE FROM agents WHERE person_id=?`,
	} {
		if _, err := tx.Exec(q, personID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM login_tokens WHERE email=?`, p.Email); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM persons WHERE id=?`, personID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// errNoRows normalizes sql.ErrNoRows to ErrNotFound.
func errNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
