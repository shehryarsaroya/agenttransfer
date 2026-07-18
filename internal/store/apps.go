package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// schemaOwnerVerificationV7 records why owner_verified is true. Historical
// verified rows with a real mailbox retain the legacy mail/storage tier, but
// are not treated as fresh mailbox proof for hosting; the old admin-created
// ownerless shape is deliberately cleared.
const schemaOwnerVerificationV7 = `
ALTER TABLE agents ADD COLUMN owner_verified_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN owner_verification_method TEXT NOT NULL DEFAULT '';
UPDATE agents
SET owner_verified_at=created_at, owner_verification_method='legacy'
WHERE owner_verified=1 AND TRIM(owner_email)<>'';
UPDATE agents
SET owner_verified=0, owner_verified_at=0, owner_verification_method=''
WHERE owner_verified=1 AND TRIM(owner_email)='';
`

// schemaAppsV8 gives every agent at most one durable public app identity. An
// app owns immutable deployments; static deployments own path→blob mappings.
// Cascades make agent deletion reap every piece of app metadata, while blob
// bytes remain governed by the central reference predicate in store.go.
const schemaAppsV8 = `
CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE CASCADE,
  slug TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'stopped',
  active_deployment_id TEXT NOT NULL DEFAULT '',
  runtime_id TEXT NOT NULL DEFAULT '',
  upstream TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  container_port INTEGER NOT NULL DEFAULT 0,
  env_keys_json TEXT NOT NULL DEFAULT '[]',
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apps_slug ON apps(slug);

CREATE TABLE IF NOT EXISTS app_deployments (
  id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'staged',
  source_sha256 TEXT NOT NULL DEFAULT '',
  source_size INTEGER NOT NULL DEFAULT 0,
  config_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  activated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_app_deployments_app
  ON app_deployments(app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_deployments_source
  ON app_deployments(source_sha256) WHERE source_sha256<>'';

CREATE TABLE IF NOT EXISTS app_files (
  deployment_id TEXT NOT NULL REFERENCES app_deployments(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  mime TEXT NOT NULL DEFAULT 'application/octet-stream',
  size INTEGER NOT NULL,
  PRIMARY KEY (deployment_id, path)
);
CREATE INDEX IF NOT EXISTS idx_app_files_sha ON app_files(sha256);
`

// schemaAppContainerHistoryV9 keeps one conservative bit after releases are
// reset. Runner-managed /data is keyed by app ID and intentionally survives a
// non-purging delete, so future purges/agent deletion must still know that a
// runner may own state even when no deployment rows remain.
const schemaAppContainerHistoryV9 = `
ALTER TABLE apps ADD COLUMN ever_container INTEGER NOT NULL DEFAULT 0;
UPDATE apps SET ever_container=1 WHERE kind='container' OR EXISTS (
  SELECT 1 FROM app_deployments d WHERE d.app_id=apps.id AND d.kind='container'
);
`

// schemaVerifyTokenOwnerV10 binds each owner challenge to the mailbox that
// was nominated when the token was minted. This closes the race where an old
// click could otherwise verify a newly substituted owner address.
const schemaVerifyTokenOwnerV10 = `
ALTER TABLE verify_tokens ADD COLUMN owner_email TEXT NOT NULL DEFAULT '';
UPDATE verify_tokens SET owner_email=COALESCE(
  (SELECT owner_email FROM agents WHERE agents.id=verify_tokens.agent_id), ''
);
`

const (
	AppKindStatic    = "static"
	AppKindContainer = "container"

	AppStatusStopped  = "stopped"
	AppStatusStaged   = "staged"
	AppStatusStarting = "starting"
	AppStatusRunning  = "running"
	AppStatusError    = "error"

	DeploymentStatusStaged   = "staged"
	DeploymentStatusActive   = "active"
	DeploymentStatusInactive = "inactive"
	DeploymentStatusFailed   = "failed"
)

var (
	// ErrAppDeploymentActive prevents deleting the release selected by an app.
	ErrAppDeploymentActive = errors.New("app deployment is active")
	// ErrInvalidAppFile identifies malformed or dishonest static file metadata.
	ErrInvalidAppFile = errors.New("invalid app file")
)

// App is the durable public identity and current runtime projection for one
// agent. Slug never changes unless the app is fully purged and recreated.
type App struct {
	ID                 string `json:"id"`
	AgentID            string `json:"agent_id"`
	Slug               string `json:"slug"`
	Kind               string `json:"kind,omitempty"`
	Status             string `json:"status"`
	ActiveDeploymentID string `json:"active_deployment_id,omitempty"`
	RuntimeID          string `json:"runtime_id,omitempty"`
	Upstream           string `json:"upstream,omitempty"`
	Image              string `json:"image,omitempty"`
	ContainerPort      int    `json:"container_port,omitempty"`
	EnvKeysJSON        string `json:"env_keys_json,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
	EverContainer      bool   `json:"-"`
}

// AppDeployment is one immutable release. Runtime status changes, but its
// kind, source and config never do.
type AppDeployment struct {
	ID          string          `json:"id"`
	AppID       string          `json:"app_id"`
	Kind        string          `json:"kind"`
	Status      string          `json:"status"`
	SourceSHA   string          `json:"source_sha256,omitempty"`
	SourceSize  int64           `json:"source_size"`
	Config      json.RawMessage `json:"config"`
	CreatedAt   int64           `json:"created_at"`
	UpdatedAt   int64           `json:"updated_at"`
	ActivatedAt int64           `json:"activated_at,omitempty"`
}

// AppFileSpec is a static release path and its already-stored blob.
type AppFileSpec struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	MIME   string `json:"mime"`
	Size   int64  `json:"size"`
}

// AppFile is a persisted static release entry.
type AppFile struct {
	DeploymentID string `json:"deployment_id"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	MIME         string `json:"mime"`
	Size         int64  `json:"size"`
}

// AppUsage reports the logical bytes retained by a release. SourceBytes is
// the uploaded source/archive; FileBytes is the expanded static file set.
type AppUsage struct {
	SourceBytes int64 `json:"source_bytes"`
	FileBytes   int64 `json:"file_bytes"`
	TotalBytes  int64 `json:"total_bytes"`
}

// AppStorageConsumer attributes retained app storage to an agent and owner
// for the admin storage view. Retained includes inactive releases; Active is
// the currently selected release only.
type AppStorageConsumer struct {
	AgentID                 string `json:"agent_id"`
	Name                    string `json:"name"`
	Email                   string `json:"email"`
	OwnerEmail              string `json:"owner_email"`
	OwnerVerified           bool   `json:"owner_verified"`
	OwnerVerificationMethod string `json:"owner_verification_method,omitempty"`
	Slug                    string `json:"slug"`
	Status                  string `json:"status"`
	Deployments             int64  `json:"deployments"`
	SourceBytes             int64  `json:"source_bytes"`
	FileBytes               int64  `json:"file_bytes"`
	TotalBytes              int64  `json:"total_bytes"`
	ActiveBytes             int64  `json:"active_bytes"`
}

const appCols = `id,agent_id,slug,kind,status,active_deployment_id,runtime_id,upstream,image,container_port,env_keys_json,last_error,created_at,updated_at,ever_container`

func scanApp(row interface{ Scan(...any) error }) (App, error) {
	var a App
	var everContainer int
	err := row.Scan(&a.ID, &a.AgentID, &a.Slug, &a.Kind, &a.Status,
		&a.ActiveDeploymentID, &a.RuntimeID, &a.Upstream, &a.Image,
		&a.ContainerPort, &a.EnvKeysJSON, &a.LastError, &a.CreatedAt, &a.UpdatedAt, &everContainer)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.EverContainer = everContainer == 1
	return a, err
}

const appDeploymentCols = `id,app_id,kind,status,source_sha256,source_size,config_json,created_at,updated_at,activated_at`
const appDeploymentColsD = `d.id,d.app_id,d.kind,d.status,d.source_sha256,d.source_size,d.config_json,d.created_at,d.updated_at,d.activated_at`

func scanAppDeployment(row interface{ Scan(...any) error }) (AppDeployment, error) {
	var d AppDeployment
	var config string
	err := row.Scan(&d.ID, &d.AppID, &d.Kind, &d.Status, &d.SourceSHA,
		&d.SourceSize, &config, &d.CreatedAt, &d.UpdatedAt, &d.ActivatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Config = json.RawMessage(config)
	return d, err
}

// EnsureApp returns the agent's app, creating it once when absent. preferredName
// must match the persisted agent name when provided; this catches stale caller
// state while retaining a convenient handler contract.
func (s *Store) EnsureApp(agentID, preferredName string) (App, error) {
	if a, err := s.AppByAgentID(agentID); err == nil {
		return a, nil
	} else if !errors.Is(err, ErrNotFound) {
		return App{}, err
	}

	tx, err := s.DB.Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()

	var persistedName string
	if err := tx.QueryRow(`SELECT name FROM agents WHERE id=?`, agentID).Scan(&persistedName); errors.Is(err, sql.ErrNoRows) {
		return App{}, ErrNotFound
	} else if err != nil {
		return App{}, err
	}
	if preferredName != "" && !strings.EqualFold(strings.TrimSpace(preferredName), persistedName) {
		return App{}, fmt.Errorf("agent name changed: persisted %q, supplied %q", persistedName, preferredName)
	}

	base, exact := dnsAppSlug(persistedName)
	for attempt := 0; attempt < 100; attempt++ {
		candidate := base
		if !exact || attempt > 0 {
			candidate = suffixedAppSlug(base, agentID, attempt)
		}
		var occupied int
		err := tx.QueryRow(`SELECT 1 FROM apps WHERE slug=?`, candidate).Scan(&occupied)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return App{}, err
		}
		ts := now()
		a := App{
			ID: NewID("app"), AgentID: agentID, Slug: candidate,
			Status: AppStatusStopped, EnvKeysJSON: "[]", CreatedAt: ts, UpdatedAt: ts,
		}
		if _, err := tx.Exec(`INSERT INTO apps(id,agent_id,slug,status,env_keys_json,created_at,updated_at)
			VALUES(?,?,?,?,?,?,?)`, a.ID, a.AgentID, a.Slug, a.Status, a.EnvKeysJSON, ts, ts); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			}
			return App{}, err
		}
		if err := tx.Commit(); err != nil {
			return App{}, err
		}
		return a, nil
	}
	return App{}, errors.New("could not allocate a unique app slug")
}

// dnsAppSlug returns a normalized DNS label and whether the original was
// already exactly safe. Changed names always receive a deterministic suffix,
// avoiding silent collisions such as foo_bar and foo-bar.
func dnsAppSlug(name string) (slug string, exact bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	exact = len(name) > 0 && len(name) <= 63 && name[0] != '-' && name[len(name)-1] != '-'
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' {
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		exact = false
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug = strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "agent"
		exact = false
	}
	if slug != name {
		exact = false
	}
	if len(slug) > 63 {
		slug = strings.TrimRight(slug[:63], "-")
		exact = false
	}
	return slug, exact
}

func suffixedAppSlug(base, agentID string, attempt int) string {
	seed := agentID
	if attempt > 0 {
		seed = fmt.Sprintf("%s:%d", agentID, attempt)
	}
	h := sha256.Sum256([]byte(seed))
	suffix := hex.EncodeToString(h[:4])
	maxBase := 63 - 1 - len(suffix)
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	base = strings.Trim(base, "-")
	if base == "" {
		base = "agent"
	}
	return base + "-" + suffix
}

// AppByAgentID returns one agent's app metadata.
func (s *Store) AppByAgentID(agentID string) (App, error) {
	return scanApp(s.DB.QueryRow(`SELECT `+appCols+` FROM apps WHERE agent_id=?`, agentID))
}

// AppBySlug resolves the durable DNS label used by host routing.
func (s *Store) AppBySlug(slug string) (App, error) {
	return scanApp(s.DB.QueryRow(`SELECT `+appCols+` FROM apps WHERE slug=?`, strings.ToLower(strings.TrimSpace(slug))))
}

// AppsWithContainerHistory returns every app that may own runner-managed
// persistent data. The quota janitor uses this complete set rather than an
// admin-oriented top-N storage view, so a zero-source image app cannot fall
// outside enforcement merely because more than 500 apps exist.
func (s *Store) AppsWithContainerHistory() ([]App, error) {
	rows, err := s.DB.Query(`SELECT ` + appCols + ` FROM apps WHERE ever_container=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// StageStaticDeployment atomically records an immutable static release and
// all of its path mappings. Every referenced blob must already exist and its
// declared size must match the blob row.
func (s *Store) StageStaticDeployment(agentID, sourceSHA string, sourceSize int64, configJSON string, files []AppFileSpec) (AppDeployment, error) {
	if len(files) == 0 {
		return AppDeployment{}, fmt.Errorf("%w: a static deployment needs at least one file", ErrInvalidAppFile)
	}
	return s.stageAppDeployment(agentID, AppKindStatic, sourceSHA, sourceSize, configJSON, files)
}

// StageContainerDeployment atomically records a container release. sourceSHA
// may be empty for registry-image deployments; runtime fields are populated
// only after the external runner succeeds.
func (s *Store) StageContainerDeployment(agentID, sourceSHA string, sourceSize int64, configJSON string, files []AppFileSpec) (AppDeployment, error) {
	return s.stageAppDeployment(agentID, AppKindContainer, sourceSHA, sourceSize, configJSON, files)
}

func (s *Store) stageAppDeployment(agentID, kind, sourceSHA string, sourceSize int64, configJSON string, files []AppFileSpec) (AppDeployment, error) {
	configJSON, err := normalizeAppConfig(configJSON)
	if err != nil {
		return AppDeployment{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return AppDeployment{}, err
	}
	defer tx.Rollback()

	var appID, activeID, appStatus string
	if err := tx.QueryRow(`SELECT id,active_deployment_id,status FROM apps WHERE agent_id=?`, agentID).
		Scan(&appID, &activeID, &appStatus); errors.Is(err, sql.ErrNoRows) {
		return AppDeployment{}, ErrNotFound
	} else if err != nil {
		return AppDeployment{}, err
	}

	sourceSHA, sourceSize, err = validateAppBlob(tx, sourceSHA, sourceSize, "deployment source")
	if err != nil {
		return AppDeployment{}, err
	}
	prepared := make([]AppFileSpec, 0, len(files))
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		f.Path, err = normalizeAppPath(f.Path)
		if err != nil {
			return AppDeployment{}, err
		}
		if seen[f.Path] {
			return AppDeployment{}, fmt.Errorf("%w: duplicate path %q", ErrInvalidAppFile, f.Path)
		}
		seen[f.Path] = true
		f.SHA256, f.Size, err = validateAppBlob(tx, f.SHA256, f.Size, "file "+f.Path)
		if err != nil {
			return AppDeployment{}, err
		}
		f.MIME = strings.TrimSpace(f.MIME)
		if f.MIME == "" {
			f.MIME = "application/octet-stream"
		}
		if len(f.MIME) > 255 {
			return AppDeployment{}, fmt.Errorf("%w: MIME type too long for %q", ErrInvalidAppFile, f.Path)
		}
		prepared = append(prepared, f)
	}

	ts := now()
	d := AppDeployment{
		ID: NewID("dep"), AppID: appID, Kind: kind, Status: DeploymentStatusStaged,
		SourceSHA: sourceSHA, SourceSize: sourceSize, Config: json.RawMessage(configJSON),
		CreatedAt: ts, UpdatedAt: ts,
	}
	if _, err := tx.Exec(`INSERT INTO app_deployments
		(id,app_id,kind,status,source_sha256,source_size,config_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, d.ID, d.AppID, d.Kind, d.Status, d.SourceSHA,
		d.SourceSize, configJSON, ts, ts); err != nil {
		return AppDeployment{}, err
	}
	if kind == AppKindContainer {
		if _, err := tx.Exec(`UPDATE apps SET ever_container=1 WHERE id=?`, appID); err != nil {
			return AppDeployment{}, err
		}
	}
	for _, f := range prepared {
		if _, err := tx.Exec(`INSERT INTO app_files(deployment_id,path,sha256,mime,size)
			VALUES(?,?,?,?,?)`, d.ID, f.Path, f.SHA256, f.MIME, f.Size); err != nil {
			return AppDeployment{}, err
		}
	}
	// Staging must not take a healthy release offline. It is visible as the app
	// status only before the app has ever activated anything.
	if activeID == "" && appStatus == AppStatusStopped {
		if _, err := tx.Exec(`UPDATE apps SET status=?,updated_at=? WHERE id=?`, AppStatusStaged, ts, appID); err != nil {
			return AppDeployment{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AppDeployment{}, err
	}
	return d, nil
}

func normalizeAppConfig(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}", nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil || obj == nil {
		return "", errors.New("app deployment config must be a JSON object")
	}
	b, err := json.Marshal(obj)
	return string(b), err
}

func normalizeAppPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 1024 || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return "", fmt.Errorf("%w: bad path %q", ErrInvalidAppFile, name)
	}
	for _, r := range name {
		if r == 0 || r < 32 || r == 127 {
			return "", fmt.Errorf("%w: control character in path", ErrInvalidAppFile)
		}
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: unsafe path %q", ErrInvalidAppFile, name)
	}
	return clean, nil
}

func validateAppBlob(tx *sql.Tx, rawSHA string, declaredSize int64, what string) (string, int64, error) {
	sha := strings.ToLower(strings.TrimSpace(rawSHA))
	sha = strings.TrimPrefix(sha, "sha256:")
	if sha == "" {
		if declaredSize != 0 {
			return "", 0, fmt.Errorf("%s has size without a blob", what)
		}
		return "", 0, nil
	}
	if len(sha) != 64 {
		return "", 0, fmt.Errorf("%s has invalid sha256", what)
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return "", 0, fmt.Errorf("%s has invalid sha256", what)
	}
	var actual int64
	if err := tx.QueryRow(`SELECT size FROM blobs WHERE sha256=?`, sha).Scan(&actual); errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("%s blob: %w", what, ErrNotFound)
	} else if err != nil {
		return "", 0, err
	}
	if declaredSize != actual {
		return "", 0, fmt.Errorf("%s size mismatch: declared %d, stored %d", what, declaredSize, actual)
	}
	return sha, actual, nil
}

// ActivateAppDeployment atomically selects a staged release. Static releases
// become immediately runnable; containers enter "starting" until SetAppRuntime
// records the runner-issued endpoint.
func (s *Store) ActivateAppDeployment(agentID, deploymentID string) (App, AppDeployment, error) {
	return s.activateAppDeployment(agentID, deploymentID, "", "", "", 0, nil, false)
}

// SetAppRuntime records a successful container launch and atomically makes its
// deployment current, so host routing never observes a runtime paired with the
// wrong release. Only environment key names are retained, never secret values.
func (s *Store) SetAppRuntime(agentID, deploymentID, runtimeID, upstream, image string, port int, envKeys []string) (App, AppDeployment, error) {
	if strings.TrimSpace(runtimeID) == "" || strings.TrimSpace(upstream) == "" {
		return App{}, AppDeployment{}, errors.New("runtime id and upstream are required")
	}
	if port < 0 || port > 65535 {
		return App{}, AppDeployment{}, errors.New("container port must be between 0 and 65535")
	}
	return s.activateAppDeployment(agentID, deploymentID, runtimeID, upstream, image, port, envKeys, true)
}

// RefreshAppRuntimeUpstream updates the runner-approved endpoint observed for
// the exact active runtime. Persisting the live value prevents a stale
// published port or bridge address from routing to a different process.
func (s *Store) RefreshAppRuntimeUpstream(agentID, runtimeID, upstream string) error {
	if strings.TrimSpace(runtimeID) == "" || strings.TrimSpace(upstream) == "" {
		return errors.New("runtime id and upstream are required")
	}
	res, err := s.DB.Exec(`UPDATE apps SET upstream=?,updated_at=?
		WHERE agent_id=? AND runtime_id=? AND status=?`,
		upstream, now(), agentID, runtimeID, AppStatusRunning)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) activateAppDeployment(agentID, deploymentID, runtimeID, upstream, image string, port int, envKeys []string, runtime bool) (App, AppDeployment, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return App{}, AppDeployment{}, err
	}
	defer tx.Rollback()

	a, err := scanApp(tx.QueryRow(`SELECT `+appCols+` FROM apps WHERE agent_id=?`, agentID))
	if err != nil {
		return App{}, AppDeployment{}, err
	}
	d, err := scanAppDeployment(tx.QueryRow(`SELECT `+appDeploymentCols+` FROM app_deployments WHERE id=? AND app_id=?`, deploymentID, a.ID))
	if err != nil {
		return App{}, AppDeployment{}, err
	}
	if runtime && d.Kind != AppKindContainer {
		return App{}, AppDeployment{}, errors.New("runtime metadata requires a container deployment")
	}
	if !runtime && d.Kind != AppKindStatic && d.Kind != AppKindContainer {
		return App{}, AppDeployment{}, fmt.Errorf("unknown deployment kind %q", d.Kind)
	}

	ts := now()
	if a.ActiveDeploymentID != "" && a.ActiveDeploymentID != d.ID {
		if _, err := tx.Exec(`UPDATE app_deployments SET status=?,updated_at=? WHERE id=?`,
			DeploymentStatusInactive, ts, a.ActiveDeploymentID); err != nil {
			return App{}, AppDeployment{}, err
		}
	}
	d.Status = DeploymentStatusActive
	d.UpdatedAt, d.ActivatedAt = ts, ts
	if _, err := tx.Exec(`UPDATE app_deployments SET status=?,updated_at=?,activated_at=? WHERE id=?`,
		d.Status, ts, ts, d.ID); err != nil {
		return App{}, AppDeployment{}, err
	}

	a.Kind = d.Kind
	a.ActiveDeploymentID = d.ID
	a.LastError = ""
	a.UpdatedAt = ts
	if runtime {
		a.Status = AppStatusRunning
		a.RuntimeID = strings.TrimSpace(runtimeID)
		a.Upstream = strings.TrimSpace(upstream)
		a.Image = strings.TrimSpace(image)
		a.ContainerPort = port
		a.EnvKeysJSON, err = normalizedEnvKeys(envKeys)
		if err != nil {
			return App{}, AppDeployment{}, err
		}
	} else {
		a.RuntimeID, a.Upstream, a.Image = "", "", ""
		a.ContainerPort, a.EnvKeysJSON = 0, "[]"
		if d.Kind == AppKindContainer {
			a.Status = AppStatusStarting
		} else {
			a.Status = AppStatusRunning
		}
	}
	if _, err := tx.Exec(`UPDATE apps SET kind=?,status=?,active_deployment_id=?,runtime_id=?,
		upstream=?,image=?,container_port=?,env_keys_json=?,last_error='',updated_at=? WHERE id=?`,
		a.Kind, a.Status, a.ActiveDeploymentID, a.RuntimeID, a.Upstream, a.Image,
		a.ContainerPort, a.EnvKeysJSON, ts, a.ID); err != nil {
		return App{}, AppDeployment{}, err
	}
	if err := tx.Commit(); err != nil {
		return App{}, AppDeployment{}, err
	}
	return a, d, nil
}

func normalizedEnvKeys(keys []string) (string, error) {
	if len(keys) > 128 {
		return "", errors.New("too many environment keys")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 256 {
			return "", errors.New("invalid environment key")
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	b, err := json.Marshal(out)
	return string(b), err
}

// SetAppError records a failed deployment/runtime attempt. A failed staged
// replacement does not take an older healthy active release offline.
func (s *Store) SetAppError(agentID, deploymentID, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 4096 {
		message = message[:4096]
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var appID, activeID, status string
	if err := tx.QueryRow(`SELECT id,active_deployment_id,status FROM apps WHERE agent_id=?`, agentID).
		Scan(&appID, &activeID, &status); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE app_deployments SET status=?,updated_at=? WHERE id=? AND app_id=?`,
		DeploymentStatusFailed, now(), deploymentID, appID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if activeID == "" || activeID == deploymentID {
		status = AppStatusError
	}
	if _, err := tx.Exec(`UPDATE apps SET status=?,last_error=?,updated_at=? WHERE id=?`, status, message, now(), appID); err != nil {
		return err
	}
	return tx.Commit()
}

// StopApp removes the app from public routing while retaining its active
// release and runtime identity for inspection/cleanup or a later restart.
func (s *Store) StopApp(agentID string) (App, error) {
	res, err := s.DB.Exec(`UPDATE apps SET status=?,updated_at=? WHERE agent_id=?`, AppStatusStopped, now(), agentID)
	if err != nil {
		return App{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return App{}, ErrNotFound
	}
	return s.AppByAgentID(agentID)
}

// AppDeploymentByID returns a deployment only when it belongs to agentID.
func (s *Store) AppDeploymentByID(agentID, deploymentID string) (AppDeployment, error) {
	return scanAppDeployment(s.DB.QueryRow(`SELECT `+appDeploymentColsD+` FROM app_deployments d
		JOIN apps a ON a.id=d.app_id WHERE a.agent_id=? AND d.id=?`, agentID, deploymentID))
}

// ActiveAppDeployment returns the selected deployment, even when the app is
// stopped. Public routing must additionally require app.Status == "running".
func (s *Store) ActiveAppDeployment(agentID string) (AppDeployment, error) {
	return scanAppDeployment(s.DB.QueryRow(`SELECT `+appDeploymentColsD+` FROM app_deployments d
		JOIN apps a ON a.id=d.app_id WHERE a.agent_id=? AND d.id=a.active_deployment_id`, agentID))
}

// AppDeployments lists newest releases first.
func (s *Store) AppDeployments(agentID string, limit int) ([]AppDeployment, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.DB.Query(`SELECT `+appDeploymentColsD+` FROM app_deployments d
		JOIN apps a ON a.id=d.app_id WHERE a.agent_id=? ORDER BY d.created_at DESC,d.rowid DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployment{}
	for rows.Next() {
		d, err := scanAppDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AppFiles lists a static deployment's files in path order.
func (s *Store) AppFiles(agentID, deploymentID string) ([]AppFile, error) {
	rows, err := s.DB.Query(`SELECT f.deployment_id,f.path,f.sha256,f.mime,f.size
		FROM app_files f JOIN app_deployments d ON d.id=f.deployment_id
		JOIN apps a ON a.id=d.app_id WHERE a.agent_id=? AND d.id=? ORDER BY f.path`, agentID, deploymentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppFile{}
	for rows.Next() {
		var f AppFile
		if err := rows.Scan(&f.DeploymentID, &f.Path, &f.SHA256, &f.MIME, &f.Size); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AppFileByPath resolves one static path while enforcing agent/deployment
// ownership in the query.
func (s *Store) AppFileByPath(agentID, deploymentID, filePath string) (AppFile, error) {
	filePath, err := normalizeAppPath(filePath)
	if err != nil {
		return AppFile{}, ErrNotFound
	}
	var f AppFile
	err = s.DB.QueryRow(`SELECT f.deployment_id,f.path,f.sha256,f.mime,f.size
		FROM app_files f JOIN app_deployments d ON d.id=f.deployment_id
		JOIN apps a ON a.id=d.app_id WHERE a.agent_id=? AND d.id=? AND f.path=?`,
		agentID, deploymentID, filePath).
		Scan(&f.DeploymentID, &f.Path, &f.SHA256, &f.MIME, &f.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return AppFile{}, ErrNotFound
	}
	return f, err
}

// ActiveAppUsage reports logical bytes for only the selected release.
func (s *Store) ActiveAppUsage(agentID string) (AppUsage, error) {
	var u AppUsage
	err := s.DB.QueryRow(`SELECT COALESCE(d.source_size,0),COALESCE(SUM(f.size),0)
		FROM apps a LEFT JOIN app_deployments d ON d.id=a.active_deployment_id
		LEFT JOIN app_files f ON f.deployment_id=d.id WHERE a.agent_id=?
		GROUP BY a.id,d.source_size`, agentID).Scan(&u.SourceBytes, &u.FileBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	total, err := addStorageBytes(u.SourceBytes, u.FileBytes)
	if err != nil {
		return u, err
	}
	u.TotalBytes = total
	return u, nil
}

// AppSourceUsage is the active release's logical uploaded source size.
func (s *Store) AppSourceUsage(agentID string) (int64, error) {
	u, err := s.ActiveAppUsage(agentID)
	return u.SourceBytes, err
}

// RetainedAppUsage includes staged, failed and inactive releases still held.
func (s *Store) RetainedAppUsage(agentID string) (AppUsage, error) {
	var appID string
	if err := s.DB.QueryRow(`SELECT id FROM apps WHERE agent_id=?`, agentID).Scan(&appID); errors.Is(err, sql.ErrNoRows) {
		return AppUsage{}, ErrNotFound
	} else if err != nil {
		return AppUsage{}, err
	}
	var u AppUsage
	if err := s.DB.QueryRow(`SELECT COALESCE(SUM(source_size),0) FROM app_deployments WHERE app_id=?`, appID).Scan(&u.SourceBytes); err != nil {
		return u, err
	}
	if err := s.DB.QueryRow(`SELECT COALESCE(SUM(f.size),0) FROM app_files f
		JOIN app_deployments d ON d.id=f.deployment_id WHERE d.app_id=?`, appID).Scan(&u.FileBytes); err != nil {
		return u, err
	}
	total, err := addStorageBytes(u.SourceBytes, u.FileBytes)
	if err != nil {
		return u, err
	}
	u.TotalBytes = total
	return u, nil
}

// TopAppStorageConsumers attributes all retained logical app bytes to agents.
func (s *Store) TopAppStorageConsumers(limit int) ([]AppStorageConsumer, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.DB.Query(`SELECT ag.id,ag.name,ag.email,ag.owner_email,ag.owner_verified,
		ag.owner_verification_method,a.slug,a.status,
		COALESCE(ds.deployments,0),COALESCE(ds.source_bytes,0),COALESCE(fs.file_bytes,0),
		COALESCE(ds.source_bytes,0)+COALESCE(fs.file_bytes,0) AS total_bytes,
		COALESCE(ad.source_size,0)+COALESCE(af.file_bytes,0) AS active_bytes
		FROM apps a JOIN agents ag ON ag.id=a.agent_id
		LEFT JOIN (SELECT app_id,COUNT(*) deployments,SUM(source_size) source_bytes
			FROM app_deployments GROUP BY app_id) ds ON ds.app_id=a.id
		LEFT JOIN (SELECT d.app_id,SUM(f.size) file_bytes FROM app_deployments d
			JOIN app_files f ON f.deployment_id=d.id GROUP BY d.app_id) fs ON fs.app_id=a.id
		LEFT JOIN app_deployments ad ON ad.id=a.active_deployment_id
		LEFT JOIN (SELECT deployment_id,SUM(size) file_bytes FROM app_files GROUP BY deployment_id) af
			ON af.deployment_id=a.active_deployment_id
		ORDER BY active_bytes DESC,total_bytes DESC,a.created_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppStorageConsumer{}
	for rows.Next() {
		var c AppStorageConsumer
		var verified int
		if err := rows.Scan(&c.AgentID, &c.Name, &c.Email, &c.OwnerEmail, &verified,
			&c.OwnerVerificationMethod, &c.Slug, &c.Status, &c.Deployments,
			&c.SourceBytes, &c.FileBytes, &c.TotalBytes, &c.ActiveBytes); err != nil {
			return nil, err
		}
		c.OwnerVerified = verified == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteAppDeployment removes one non-active release and its file mappings.
func (s *Store) DeleteAppDeployment(agentID, deploymentID string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var appID, activeID string
	if err := tx.QueryRow(`SELECT id,active_deployment_id FROM apps WHERE agent_id=?`, agentID).
		Scan(&appID, &activeID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if activeID == deploymentID {
		return ErrAppDeploymentActive
	}
	res, err := tx.Exec(`DELETE FROM app_deployments WHERE id=? AND app_id=?`, deploymentID, appID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// PruneInactiveAppDeployments retains the newest keep non-active releases and
// deletes the rest. The active deployment is never eligible.
func (s *Store) PruneInactiveAppDeployments(agentID string, keep int) (int, error) {
	if keep < 0 {
		return 0, errors.New("keep must be non-negative")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var appID, activeID string
	if err := tx.QueryRow(`SELECT id,active_deployment_id FROM apps WHERE agent_id=?`, agentID).
		Scan(&appID, &activeID); errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	} else if err != nil {
		return 0, err
	}
	rows, err := tx.Query(`SELECT id FROM app_deployments WHERE app_id=? AND id<>?
		ORDER BY created_at DESC,rowid DESC`, appID, activeID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	deleted := 0
	for _, id := range ids[min(keep, len(ids)):] {
		if _, err := tx.Exec(`DELETE FROM app_deployments WHERE id=? AND app_id=?`, id, appID); err != nil {
			return deleted, err
		}
		deleted++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// ResetApp removes every release and runtime projection while retaining the
// durable app identity. Keeping the app ID is what lets a later deployment
// reattach the same runner-managed persistent /data after an app is removed
// without purge_data. EverContainer is intentionally retained, so later
// purge/agent deletion still require the runner instead of silently orphaning
// retained data.
func (s *Store) ResetApp(agentID string) (App, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()
	a, err := scanApp(tx.QueryRow(`SELECT `+appCols+` FROM apps WHERE agent_id=?`, agentID))
	if err != nil {
		return a, err
	}
	if _, err := tx.Exec(`DELETE FROM app_deployments WHERE app_id=?`, a.ID); err != nil {
		return a, err
	}
	ts := now()
	if _, err := tx.Exec(`UPDATE apps SET status=?,active_deployment_id='',runtime_id='',
		upstream='',image='',container_port=0,env_keys_json='[]',last_error='',updated_at=? WHERE id=?`,
		AppStatusStopped, ts, a.ID); err != nil {
		return a, err
	}
	if err := tx.Commit(); err != nil {
		return a, err
	}
	return s.AppByAgentID(agentID)
}

// PurgeApp removes the app identity and every deployment/file mapping. The
// returned pre-delete metadata lets a caller stop an external runtime.
func (s *Store) PurgeApp(agentID string) (App, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return App{}, err
	}
	defer tx.Rollback()
	a, err := scanApp(tx.QueryRow(`SELECT `+appCols+` FROM apps WHERE agent_id=?`, agentID))
	if err != nil {
		return App{}, err
	}
	if _, err := tx.Exec(`DELETE FROM apps WHERE id=?`, a.ID); err != nil {
		return App{}, err
	}
	if err := tx.Commit(); err != nil {
		return App{}, err
	}
	return a, nil
}
