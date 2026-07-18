package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func mustAgent(t *testing.T, s *Store, name, owner string, verified bool) Agent {
	t.Helper()
	a, _, err := s.CreateAgent(name, owner, verified)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnsureAppSlugNormalizationCollisionAndDurability(t *testing.T) {
	s := newStore(t)

	safeAgent := mustAgent(t, s, "alpha-bot", "", false)
	safe, err := s.EnsureApp(safeAgent.ID, safeAgent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if safe.Slug != "alpha-bot" {
		t.Fatalf("DNS-safe name should stay exact: %q", safe.Slug)
	}

	changedAgent := mustAgent(t, s, "alpha_bot", "", false)
	changed, err := s.EnsureApp(changedAgent.ID, changedAgent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Slug == "alpha-bot" || !strings.HasPrefix(changed.Slug, "alpha-bot-") {
		t.Fatalf("normalized name must carry a stable suffix: %q", changed.Slug)
	}
	if len(changed.Slug) > 63 || !dnsLabelRE.MatchString(changed.Slug) {
		t.Fatalf("not a DNS label: %q", changed.Slug)
	}
	again, err := s.EnsureApp(changedAgent.ID, changedAgent.Name)
	if err != nil || again.ID != changed.ID || again.Slug != changed.Slug {
		t.Fatalf("EnsureApp was not durable: got %+v err=%v, want %+v", again, err, changed)
	}

	// Occupy a safe agent's exact label to exercise the collision path. This is
	// possible after imports/migrations even though agent names themselves are
	// unique, and the allocator must still never fail or steal the slug.
	holderAgent := mustAgent(t, s, "holder", "", false)
	holder, err := s.EnsureApp(holderAgent.ID, holderAgent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE apps SET slug='collision' WHERE id=?`, holder.ID); err != nil {
		t.Fatal(err)
	}
	collisionAgent := mustAgent(t, s, "collision", "", false)
	collided, err := s.EnsureApp(collisionAgent.ID, collisionAgent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if collided.Slug == "collision" || !strings.HasPrefix(collided.Slug, "collision-") {
		t.Fatalf("expected deterministic collision suffix, got %q", collided.Slug)
	}

	longAgent := mustAgent(t, s, strings.Repeat("a", 64), "", false)
	longApp, err := s.EnsureApp(longAgent.ID, longAgent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(longApp.Slug) > 63 || !dnsLabelRE.MatchString(longApp.Slug) {
		t.Fatalf("long name produced invalid slug %q", longApp.Slug)
	}
}

func TestActiveAppUsageRejectsInt64Overflow(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "overflow-usage", "", false)
	app, err := s.EnsureApp(a.ID, a.Name)
	if err != nil {
		t.Fatal(err)
	}
	depID := "dep_overflow_usage"
	if _, err := s.DB.Exec(`INSERT INTO app_deployments
		(id,app_id,kind,status,source_size,created_at,updated_at)
		VALUES(?,?,?,'active',?,?,?)`, depID, app.ID, AppKindStatic, maxInt64, now(), now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO app_files(deployment_id,path,sha256,mime,size)
		VALUES(?, 'index.html', 'overflow-sha', 'text/html', 1)`, depID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE apps SET active_deployment_id=? WHERE id=?`, depID, app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveAppUsage(a.ID); err == nil {
		t.Fatal("overflowing active app usage was accepted")
	}
}

func TestAppStaticStageActivateLookupUsageAndGC(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "site-agent", "owner@example.com", false)
	app, err := s.EnsureApp(a.ID, a.Name)
	if err != nil {
		t.Fatal(err)
	}

	sourceSHA, sourceSize := put(t, s, "static source archive")
	indexSHA, indexSize := put(t, s, "<h1>Hello</h1>")
	cssSHA, cssSize := put(t, s, "body { color: navy; }")
	d, err := s.StageStaticDeployment(a.ID, "sha256:"+sourceSHA, sourceSize, `{"spa":true}`, []AppFileSpec{
		{Path: "index.html", SHA256: indexSHA, MIME: "text/html; charset=utf-8", Size: indexSize},
		{Path: "assets/site.css", SHA256: cssSHA, MIME: "text/css", Size: cssSize},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != DeploymentStatusStaged || d.SourceSHA != sourceSHA {
		t.Fatalf("bad staged deployment: %+v", d)
	}
	app, err = s.AppByAgentID(a.ID)
	if err != nil || app.Status != AppStatusStaged {
		t.Fatalf("new app should expose staged state: %+v err=%v", app, err)
	}

	files, err := s.AppFiles(a.ID, d.ID)
	if err != nil || len(files) != 2 || files[0].Path != "assets/site.css" || files[1].Path != "index.html" {
		t.Fatalf("unexpected files: %+v err=%v", files, err)
	}
	index, err := s.AppFileByPath(a.ID, d.ID, "index.html")
	if err != nil || index.SHA256 != indexSHA || index.Size != indexSize {
		t.Fatalf("lookup failed: %+v err=%v", index, err)
	}
	if _, err := s.AppFileByPath(a.ID, d.ID, "../index.html"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unsafe lookup should be hidden as not found, got %v", err)
	}

	// Staged releases are durable GC roots, not just active ones.
	for _, sha := range []string{sourceSHA, indexSHA, cssSHA} {
		if !survivesGC(t, s, sha) {
			t.Fatalf("staged app blob %s was garbage-collected", sha)
		}
	}

	app, active, err := s.ActivateAppDeployment(a.ID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != AppStatusRunning || app.Kind != AppKindStatic || app.ActiveDeploymentID != d.ID || active.Status != DeploymentStatusActive {
		t.Fatalf("activation was not atomic: app=%+v deployment=%+v", app, active)
	}
	usage, err := s.ActiveAppUsage(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := indexSize + cssSize
	if usage.SourceBytes != sourceSize || usage.FileBytes != wantFiles || usage.TotalBytes != sourceSize+wantFiles {
		t.Fatalf("bad active usage: %+v", usage)
	}
	if got, err := s.AppSourceUsage(a.ID); err != nil || got != sourceSize {
		t.Fatalf("source usage=%d err=%v, want %d", got, err, sourceSize)
	}

	consumers, err := s.TopAppStorageConsumers(10)
	if err != nil || len(consumers) != 1 {
		t.Fatalf("admin attribution: %+v err=%v", consumers, err)
	}
	if consumers[0].AgentID != a.ID || consumers[0].ActiveBytes != usage.TotalBytes || consumers[0].TotalBytes != usage.TotalBytes {
		t.Fatalf("bad admin attribution: %+v", consumers[0])
	}
	if err := s.DeleteAppDeployment(a.ID, d.ID); !errors.Is(err, ErrAppDeploymentActive) {
		t.Fatalf("active deletion should be refused, got %v", err)
	}
}

func TestAppStageRollsBackOnInvalidFile(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "atomic-stage", "", false)
	if _, err := s.EnsureApp(a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "valid")
	_, err := s.StageStaticDeployment(a.ID, "", 0, `{}`, []AppFileSpec{
		{Path: "index.html", SHA256: sha, Size: size},
		{Path: "missing.js", SHA256: strings.Repeat("0", 64), Size: 1},
	})
	if err == nil {
		t.Fatal("deployment with a missing blob succeeded")
	}
	deployments, err := s.AppDeployments(a.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments) != 0 {
		t.Fatalf("partial deployment survived rollback: %+v", deployments)
	}
	var files int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM app_files`).Scan(&files); err != nil || files != 0 {
		t.Fatalf("partial file mappings survived rollback: count=%d err=%v", files, err)
	}
}

func TestAppContainerRuntimeErrorStopAndPrune(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "runner-agent", "owner@example.com", false)
	if _, err := s.EnsureApp(a.ID, a.Name); err != nil {
		t.Fatal(err)
	}

	old, err := s.StageContainerDeployment(a.ID, "", 0, `{"image":"example/old:1"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	app, active, err := s.SetAppRuntime(a.ID, old.ID, "ctr-old", "unix:///run/old.sock", "example/old:1", 8080, []string{"TOKEN", "API_URL", "TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Status != AppStatusRunning || app.RuntimeID != "ctr-old" || active.Status != DeploymentStatusActive {
		t.Fatalf("bad runtime activation: app=%+v deployment=%+v", app, active)
	}
	if err := s.RefreshAppRuntimeUpstream(a.ID, "ctr-old", "http://127.0.0.1:32001"); err != nil {
		t.Fatal(err)
	}
	app, _ = s.AppByAgentID(a.ID)
	if app.Upstream != "http://127.0.0.1:32001" {
		t.Fatalf("runtime endpoint was not refreshed: %+v", app)
	}
	if err := s.RefreshAppRuntimeUpstream(a.ID, "stale-runtime", "http://127.0.0.1:32002"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale runtime refresh error = %v, want ErrNotFound", err)
	}
	var keys []string
	if err := json.Unmarshal([]byte(app.EnvKeysJSON), &keys); err != nil || len(keys) != 2 || keys[0] != "API_URL" || keys[1] != "TOKEN" {
		t.Fatalf("environment keys should be names-only, sorted and unique: %q err=%v", app.EnvKeysJSON, err)
	}

	failed, err := s.StageContainerDeployment(a.ID, "", 0, `{"image":"example/bad:1"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAppError(a.ID, failed.ID, "image pull failed"); err != nil {
		t.Fatal(err)
	}
	app, _ = s.AppByAgentID(a.ID)
	if app.Status != AppStatusRunning || app.LastError != "image pull failed" || app.ActiveDeploymentID != old.ID {
		t.Fatalf("failed replacement disrupted healthy app: %+v", app)
	}

	newer, err := s.StageContainerDeployment(a.ID, "", 0, `{"image":"example/new:2"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	app, _, err = s.SetAppRuntime(a.ID, newer.ID, "ctr-new", "unix:///run/new.sock", "example/new:2", 3000, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldAfter, err := s.AppDeploymentByID(a.ID, old.ID)
	if err != nil || oldAfter.Status != DeploymentStatusInactive {
		t.Fatalf("old deployment not made inactive: %+v err=%v", oldAfter, err)
	}
	if _, err := s.StopApp(a.ID); err != nil {
		t.Fatal(err)
	}
	stopped, _ := s.AppByAgentID(a.ID)
	if stopped.Status != AppStatusStopped || stopped.ActiveDeploymentID != newer.ID || stopped.RuntimeID != "ctr-new" {
		t.Fatalf("stop should retain cleanup/restart metadata: %+v", stopped)
	}

	deleted, err := s.PruneInactiveAppDeployments(a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 { // old + failed are inactive candidates; retain newest one.
		t.Fatalf("pruned %d deployments, want 1", deleted)
	}
	deployments, err := s.AppDeployments(a.ID, 20)
	if err != nil || len(deployments) != 2 {
		t.Fatalf("unexpected deployments after prune: %+v err=%v", deployments, err)
	}
}

func TestAppPurgeAndAgentDeleteReleaseBlobs(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "purge-agent", "", false)
	app, err := s.EnsureApp(a.ID, a.Name)
	if err != nil {
		t.Fatal(err)
	}
	sourceSHA, sourceSize := put(t, s, "purge source")
	fileSHA, fileSize := put(t, s, "purge file")
	d, err := s.StageStaticDeployment(a.ID, sourceSHA, sourceSize, `{}`, []AppFileSpec{{
		Path: "index.html", SHA256: fileSHA, MIME: "text/html", Size: fileSize,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ActivateAppDeployment(a.ID, d.ID); err != nil {
		t.Fatal(err)
	}
	purged, err := s.PurgeApp(a.ID)
	if err != nil || purged.ID != app.ID {
		t.Fatalf("purge: %+v err=%v", purged, err)
	}
	if _, err := s.AppByAgentID(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("app survived purge: %v", err)
	}
	for _, sha := range []string{sourceSHA, fileSHA} {
		if survivesGC(t, s, sha) {
			t.Fatalf("blob %s survived after app purge", sha)
		}
	}

	b := mustAgent(t, s, "delete-agent", "", false)
	if _, err := s.EnsureApp(b.ID, b.Name); err != nil {
		t.Fatal(err)
	}
	bSHA, bSize := put(t, s, "delete with agent")
	bDep, err := s.StageStaticDeployment(b.ID, "", 0, `{}`, []AppFileSpec{{Path: "index.html", SHA256: bSHA, Size: bSize}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ActivateAppDeployment(b.ID, bDep.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteAgent(b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppByAgentID(b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("app metadata survived agent cascade: %v", err)
	}
	if survivesGC(t, s, bSHA) {
		t.Fatal("app file blob survived agent cascade")
	}
}

func TestResetAppRetainsIdentityButDropsReleases(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "reset-agent", "", false)
	before, err := s.EnsureApp(a.ID, a.Name)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.StageContainerDeployment(a.ID, "", 0, `{"image":"example/app:1"}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetAppRuntime(a.ID, d.ID, "ctr-reset", "http://127.0.0.1:1234", "example/app:1", 8080, nil); err != nil {
		t.Fatal(err)
	}
	after, err := s.ResetApp(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || after.Slug != before.Slug || after.Kind != AppKindContainer ||
		after.Status != AppStatusStopped || after.ActiveDeploymentID != "" || after.RuntimeID != "" || !after.EverContainer {
		t.Fatalf("reset app = %+v, before = %+v", after, before)
	}
	if deployments, err := s.AppDeployments(a.ID, 10); err != nil || len(deployments) != 0 {
		t.Fatalf("deployments after reset = %+v err=%v", deployments, err)
	}
	if histories, err := s.AppsWithContainerHistory(); err != nil || len(histories) != 1 || histories[0].ID != before.ID {
		t.Fatalf("container history = %+v err=%v", histories, err)
	}
	again, err := s.EnsureApp(a.ID, a.Name)
	if err != nil || again.ID != before.ID {
		t.Fatalf("EnsureApp did not reuse reset identity: %+v err=%v", again, err)
	}
}

func TestOwnerVerificationProvenance(t *testing.T) {
	s := newStore(t)
	if legacy := (Agent{OwnerEmail: "owner@example.com", OwnerVerified: true, OwnerVerificationMethod: "legacy"}); legacy.HumanVerified() {
		t.Fatalf("ambiguous legacy provenance must be re-challenged before hosting: %+v", legacy)
	}
	operator := mustAgent(t, s, "operator-agent", "owner@example.com", true)
	if operator.OwnerVerificationMethod != "operator" || operator.HumanVerified() {
		t.Fatalf("operator assertion must not count as human verification: %+v", operator)
	}
	oldToken, err := s.CreateVerifyToken(operator.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetOwnerPending(operator.ID, "new-owner@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekVerifyToken(oldToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old mailbox token survived owner replacement: %v", err)
	}
	pending, _ := s.AgentByID(operator.ID)
	if pending.OwnerVerified || pending.OwnerVerificationMethod != "" || pending.OwnerVerifiedAt != 0 {
		t.Fatalf("pending owner retained verification: %+v", pending)
	}
	if err := s.MarkOwnerVerifiedBy(operator.ID, "email"); err != nil {
		t.Fatal(err)
	}
	verified, _ := s.AgentByID(operator.ID)
	if !verified.HumanVerified() || verified.OwnerVerificationMethod != "email" || verified.OwnerVerifiedAt == 0 {
		t.Fatalf("email challenge did not establish human verification: %+v", verified)
	}
	if err := s.MarkOwnerVerifiedBy("missing", "email"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing agent should be not found, got %v", err)
	}
}

func TestOwnerVerificationMigrationBackfill(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 6; i++ {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			t.Fatalf("legacy migration %d: %v", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, i+1)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO agents(id,name,email,key_hash,owner_email,owner_verified,created_at)
		VALUES('with-owner','with-owner','with-owner@local','x','human@example.com',1,123),
		      ('ownerless','ownerless','ownerless@local','y','',1,456)`); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	var verified int
	var at int64
	var method string
	if err := db.QueryRow(`SELECT owner_verified,owner_verified_at,owner_verification_method
		FROM agents WHERE id='with-owner'`).Scan(&verified, &at, &method); err != nil {
		t.Fatal(err)
	}
	if verified != 1 || at != 123 || method != "legacy" {
		t.Fatalf("verified legacy owner backfill = (%d,%d,%q)", verified, at, method)
	}
	if err := db.QueryRow(`SELECT owner_verified,owner_verified_at,owner_verification_method
		FROM agents WHERE id='ownerless'`).Scan(&verified, &at, &method); err != nil {
		t.Fatal(err)
	}
	if verified != 0 || at != 0 || method != "" {
		t.Fatalf("ownerless legacy assertion was not cleared = (%d,%d,%q)", verified, at, method)
	}
}

func TestSpaceFilesRemainChargedAfterFolderDelete(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "space-owner", "", false)
	sha, size := put(t, s, strings.Repeat("x", 123))
	if _, err := s.AddFile(a.ID, sha, "asset.bin", "application/octet-stream", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	sp, err := s.CreateSpace(a.ID, "durable")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSpaceEvent(sp.ID, a.Email, "file", "", sha, "asset.bin", "application/octet-stream", size); err != nil {
		t.Fatal(err)
	}
	// Reposting and retaining a folder row must still count one distinct blob.
	if _, err := s.AddSpaceEvent(sp.ID, a.Email, "file", "again", sha, "asset.bin", "application/octet-stream", size); err != nil {
		t.Fatal(err)
	}
	if used, err := s.StorageUsed(a.ID); err != nil || used != size {
		t.Fatalf("overlap counted incorrectly: used=%d size=%d err=%v", used, size, err)
	}
	if _, err := s.DeleteFile(a.ID, sha); err != nil {
		t.Fatal(err)
	}
	if used, err := s.StorageUsed(a.ID); err != nil || used != size {
		t.Fatalf("space-pinned blob escaped quota: used=%d size=%d err=%v", used, size, err)
	}
	if !survivesGC(t, s, sha) {
		t.Fatal("space event did not keep its charged blob alive")
	}
}

// Keep the test clock import exercised in this feature file as a guard that
// app deployment timestamps remain ordinary Unix seconds like the rest of the
// store (and not zero after activation).
func TestAppActivationTimestamp(t *testing.T) {
	s := newStore(t)
	a := mustAgent(t, s, "timestamp-agent", "", false)
	if _, err := s.EnsureApp(a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	sha, size := put(t, s, "timestamp")
	d, err := s.StageStaticDeployment(a.ID, "", 0, `{}`, []AppFileSpec{{Path: "index.html", SHA256: sha, Size: size}})
	if err != nil {
		t.Fatal(err)
	}
	_, d, err = s.ActivateAppDeployment(a.ID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.ActivatedAt <= time.Now().Add(-time.Minute).Unix() || d.ActivatedAt > time.Now().Add(time.Minute).Unix() {
		t.Fatalf("implausible activation timestamp: %d", d.ActivatedAt)
	}
}
