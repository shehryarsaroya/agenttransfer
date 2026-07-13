package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

const (
	maxAppFiles = 50_000
	maxAppDepth = 32
)

type appDeployRequest struct {
	Kind       string            `json:"kind"`
	Source     string            `json:"source"`
	Image      string            `json:"image"`
	Port       int               `json:"port"`
	Env        map[string]string `json:"env"`
	Command    []string          `json:"command"`
	SPA        bool              `json:"spa"`
	HealthPath string            `json:"health_path"`
}

type staticAppConfig struct {
	SPA bool `json:"spa"`
}

type containerAppConfig struct {
	Image      string   `json:"image,omitempty"`
	Port       int      `json:"port"`
	Command    []string `json:"command,omitempty"`
	EnvKeys    []string `json:"env_keys,omitempty"`
	HealthPath string   `json:"health_path,omitempty"`
}

func validateAppHealthPath(value string) error {
	if value == "" || len(value) > 256 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\") {
		return errors.New("health_path must be an absolute path up to 256 bytes without query, fragment, or backslash")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("health_path may not contain control characters")
		}
	}
	return nil
}

func validateAppRuntimeConfig(env map[string]string, command []string) error {
	total := 0
	for key, value := range env {
		if key == "" || !(key[0] == '_' || key[0] >= 'A' && key[0] <= 'Z' || key[0] >= 'a' && key[0] <= 'z') {
			return fmt.Errorf("invalid environment variable name %q", key)
		}
		for i := 1; i < len(key); i++ {
			c := key[i]
			if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return fmt.Errorf("invalid environment variable name %q", key)
			}
		}
		if len(value) > 4096 || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("invalid value for environment variable %q", key)
		}
		total += len(key) + len(value) + 1
	}
	if total > 32<<10 {
		return errors.New("environment exceeds 32KiB")
	}
	commandTotal := 0
	for i, arg := range command {
		if len(arg) > 4096 || strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("invalid command argument %d", i)
		}
		commandTotal += len(arg)
	}
	if len(command) > 0 && command[0] == "" {
		return errors.New("command executable may not be empty")
	}
	if commandTotal > 16<<10 {
		return errors.New("command exceeds 16KiB")
	}
	return nil
}

func (s *Server) appURL(slug string) string {
	if slug == "" || s.cfg.AppDomain == "" {
		return ""
	}
	return "https://" + slug + "." + s.cfg.AppDomain
}

func (s *Server) appEligibility(agent store.Agent) (bool, string) {
	if s.cfg.AppDomain == "" {
		return false, "app hosting is disabled on this instance"
	}
	if agent.OwnerEmail == "" {
		return false, "add and verify a human owner email before hosting an app"
	}
	if !agent.HumanVerified() {
		return false, "the human owner must complete the emailed verification before hosting an app"
	}
	return true, ""
}

func (s *Server) appView(ctx context.Context, agent store.Agent, app store.App) map[string]any {
	active, _ := s.st.ActiveAppDeployment(agent.ID)
	usage, _ := s.st.ActiveAppUsage(agent.ID)
	var dataBytes int64
	var runtimeStatus any
	var observationErr string
	if s.appRunner != nil {
		var statusErr error
		var status apphost.AppStatus
		if app.RuntimeID != "" {
			status, statusErr = s.appRunner.RuntimeStatus(ctx, app.RuntimeID)
		} else if app.ID != "" {
			status, statusErr = s.appRunner.Status(ctx, app.ID)
		}
		if statusErr == nil {
			dataBytes = status.DataBytes
			runtimeStatus = status
		} else {
			observationErr = statusErr.Error()
			runtimeStatus = map[string]any{"observation_error": observationErr}
		}
	}
	envKeys := []string{}
	_ = json.Unmarshal([]byte(app.EnvKeysJSON), &envKeys)
	storage := map[string]any{
		"source_bytes": usage.SourceBytes,
		"file_bytes":   usage.FileBytes,
		"data_bytes":   dataBytes,
		"used":         usage.TotalBytes + dataBytes,
		"quota":        s.cfg.AppStorageQuota,
	}
	if observationErr != "" && app.EverContainer {
		storage["data_bytes"] = nil
		storage["used"] = nil
		storage["known_release_bytes"] = usage.TotalBytes
		storage["observation_error"] = observationErr
	}
	view := map[string]any{
		"id":          app.ID,
		"slug":        app.Slug,
		"url":         s.appURL(app.Slug),
		"kind":        app.Kind,
		"status":      app.Status,
		"deployment":  active,
		"last_error":  app.LastError,
		"env_keys":    envKeys,
		"created_at":  app.CreatedAt,
		"updated_at":  app.UpdatedAt,
		"human_gated": true,
		"storage":     storage,
	}
	if app.Kind == store.AppKindContainer {
		runtime := map[string]any{
			"id": app.RuntimeID, "image": app.Image,
			"port": app.ContainerPort,
		}
		if runtimeStatus != nil {
			runtime["observed"] = runtimeStatus
		}
		view["runtime"] = runtime
	}
	return view
}

func (s *Server) handleAppStatus(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	eligible, reason := s.appEligibility(agent)
	app, err := s.st.AppByAgentID(agent.ID)
	if errors.Is(err, store.ErrNotFound) && eligible {
		app, err = s.st.EnsureApp(agent.ID, agent.Name)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"eligible": false, "reason": reason, "domain": s.cfg.AppDomain,
			})
			return
		}
		errJSON(w, http.StatusInternalServerError, "app identity: %v", err)
		return
	}
	out := map[string]any{"eligible": eligible, "domain": s.cfg.AppDomain, "app": s.appView(r.Context(), agent, app)}
	if reason != "" {
		out["reason"] = reason
	}
	writeJSON(w, http.StatusOK, out)
}

type appDeployError struct {
	Status int
	Err    error
}

func (e *appDeployError) Error() string { return e.Err.Error() }
func appDeployFail(status int, format string, args ...any) error {
	return &appDeployError{Status: status, Err: fmt.Errorf(format, args...)}
}

func (s *Server) handleAppDeploy(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	var req appDeployRequest
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	app, deployment, err := s.deployAgentApp(r.Context(), agent, req)
	if err != nil {
		status := http.StatusBadGateway
		var deployErr *appDeployError
		if errors.As(err, &deployErr) {
			status = deployErr.Status
		}
		errJSON(w, status, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"app":        s.appView(r.Context(), agent, app),
		"deployment": deployment,
	})
}

// deployAgentApp is the single deployment service shared by REST and hosted
// MCP. Transports decode/shape responses; eligibility, serialization, quota,
// validation, activation, pruning, and receipts live here so their behavior
// cannot drift.
func (s *Server) deployAgentApp(ctx context.Context, agent store.Agent, req appDeployRequest) (store.App, store.AppDeployment, error) {
	if eligible, reason := s.appEligibility(agent); !eligible {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusForbidden, "%s", reason)
	}
	if s.diskFull() {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusInsufficientStorage, "instance storage reserve reached")
	}
	deployMu := s.uploadLock("app:" + agent.ID)
	deployMu.Lock()
	defer deployMu.Unlock()

	req.Kind = strings.ToLower(strings.TrimSpace(req.Kind))
	if req.Kind == "" {
		req.Kind = store.AppKindStatic
	}
	if req.Kind != store.AppKindStatic && req.Kind != store.AppKindContainer {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "kind must be static or container")
	}
	if len(req.Env) > 64 {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "at most 64 environment variables are allowed")
	}
	if len(req.Command) > 64 {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "command has too many arguments (max 64)")
	}
	if err := validateAppRuntimeConfig(req.Env, req.Command); err != nil {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "%v", err)
	}
	if req.Kind == store.AppKindStatic && (strings.TrimSpace(req.Image) != "" || len(req.Env) > 0 || len(req.Command) > 0) {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "image, env, and command are only valid for container apps")
	}
	if req.Kind == store.AppKindContainer && req.SPA {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "spa is only valid for static apps")
	}
	if req.HealthPath == "" {
		req.HealthPath = "/"
	}
	if err := validateAppHealthPath(req.HealthPath); err != nil {
		return store.App{}, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "%v", err)
	}

	app, err := s.st.EnsureApp(agent.ID, agent.Name)
	if err != nil {
		return app, store.AppDeployment{}, appDeployFail(http.StatusInternalServerError, "app identity: %v", err)
	}
	var retainedData int64
	if app.EverContainer {
		if s.appRunner == nil {
			return app, store.AppDeployment{}, appDeployFail(http.StatusServiceUnavailable, "container runner is unavailable; retained app data cannot be measured safely")
		}
		status, statusErr := s.appRunner.Status(ctx, app.ID)
		if statusErr != nil {
			return app, store.AppDeployment{}, appDeployFail(http.StatusBadGateway, "measure retained app data: %v", statusErr)
		}
		retainedData = status.DataBytes
		if retainedData > s.cfg.AppStorageQuota {
			return app, store.AppDeployment{}, appDeployFail(http.StatusRequestEntityTooLarge,
				"retained app data uses %d bytes (quota %d); purge data before deploying", retainedData, s.cfg.AppStorageQuota)
		}
	}

	var source store.File
	var files []store.AppFileSpec
	if strings.TrimSpace(req.Source) != "" {
		source, err = s.resolveFile(agent, req.Source)
		if err != nil {
			return app, store.AppDeployment{}, appDeployFail(http.StatusNotFound, "deployment source: %v", err)
		}
		if source.Size > s.cfg.AppBundleSize {
			return app, store.AppDeployment{}, appDeployFail(http.StatusRequestEntityTooLarge,
				"deployment archive is %d bytes (max %d)", source.Size, s.cfg.AppBundleSize)
		}
		expandedBudget := s.cfg.AppStorageQuota - source.Size - retainedData
		if expandedBudget < 0 {
			return app, store.AppDeployment{}, appDeployFail(http.StatusRequestEntityTooLarge,
				"source plus retained data uses %d bytes (quota %d)", source.Size+retainedData, s.cfg.AppStorageQuota)
		}
		files, err = s.readAppArchive(source, expandedBudget)
		if err != nil {
			if errors.Is(err, store.ErrDiskReserve) {
				return app, store.AppDeployment{}, appDeployFail(http.StatusInsufficientStorage, "deployment archive: %v", err)
			}
			return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "deployment archive: %v", err)
		}
	}
	if req.Kind == store.AppKindStatic && source.ID == "" {
		return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "a static deploy needs source (a .tar.gz already in your folder)")
	}
	if req.Kind == store.AppKindContainer && source.ID == "" && strings.TrimSpace(req.Image) == "" {
		return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "a container deploy needs source (with a Dockerfile) or image")
	}
	if req.Kind == store.AppKindContainer && source.ID != "" && strings.TrimSpace(req.Image) != "" {
		return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "provide source or image, not both")
	}

	var expanded int64
	hasIndex, hasDockerfile := false, false
	for _, f := range files {
		expanded += f.Size
		hasIndex = hasIndex || f.Path == "index.html"
		hasDockerfile = hasDockerfile || f.Path == "Dockerfile"
	}
	if source.Size+expanded+retainedData > s.cfg.AppStorageQuota {
		return app, store.AppDeployment{}, appDeployFail(http.StatusRequestEntityTooLarge,
			"app would use %d bytes (source/release %d + retained data %d; quota %d)",
			source.Size+expanded+retainedData, source.Size+expanded, retainedData, s.cfg.AppStorageQuota)
	}
	if req.Kind == store.AppKindStatic && !hasIndex {
		return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "static source needs index.html at its root")
	}
	if req.Kind == store.AppKindContainer && source.ID != "" && !hasDockerfile {
		return app, store.AppDeployment{}, appDeployFail(http.StatusBadRequest, "container source needs Dockerfile at its root")
	}

	var deployment store.AppDeployment
	if req.Kind == store.AppKindStatic {
		config, _ := json.Marshal(staticAppConfig{SPA: req.SPA})
		deployment, err = s.st.StageStaticDeployment(agent.ID, source.SHA256, source.Size, string(config), files)
		if err == nil {
			app, deployment, err = s.st.ActivateAppDeployment(agent.ID, deployment.ID)
			if err == nil && app.EverContainer && s.appRunner != nil {
				// Traffic already points at the immutable static release. Remove any
				// old/stale containers as a second idempotent phase while preserving
				// the app's /data for a future container deploy.
				if _, cleanupErr := s.appRunner.RemoveApp(ctx, app.ID); cleanupErr != nil {
					log.Printf("apphost: stale runtime cleanup after static activation for %s: %v", app.ID, cleanupErr)
				}
			}
		}
	} else {
		app, deployment, err = s.deployContainerApp(ctx, agent, app, source, files, req)
	}
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, store.ErrDiskReserve) {
			status = http.StatusInsufficientStorage
		}
		return app, deployment, appDeployFail(status, "deploy failed: %v", err)
	}
	_, _ = s.st.PruneInactiveAppDeployments(agent.ID, 1)
	_, _ = s.st.AppendReceipt(agent.Email, "app_deployed", source.SHA256, source.Size, s.appURL(app.Slug), "")
	return app, deployment, nil
}

func (s *Server) handleAppStop(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	app, err := s.stopAgentApp(r.Context(), agent)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no app")
		return
	}
	if err != nil {
		errJSON(w, http.StatusBadGateway, "stop failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": s.appView(r.Context(), agent, app)})
}

func (s *Server) stopAgentApp(ctx context.Context, agent store.Agent) (store.App, error) {
	deployMu := s.uploadLock("app:" + agent.ID)
	deployMu.Lock()
	defer deployMu.Unlock()
	app, err := s.stopAppRuntime(ctx, agent)
	if err != nil {
		return app, err
	}
	_, _ = s.st.AppendReceipt(agent.Email, "app_stopped", "", 0, s.appURL(app.Slug), "")
	return app, nil
}

func (s *Server) handleAppDelete(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	deployMu := s.uploadLock("app:" + agent.ID)
	deployMu.Lock()
	defer deployMu.Unlock()
	app, err := s.st.AppByAgentID(agent.ID)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no app")
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "load app: %v", err)
		return
	}
	purgeData := r.URL.Query().Get("purge_data") == "1" || r.URL.Query().Get("purge_data") == "true"
	if purgeData {
		if err := s.purgeAppData(r.Context(), agent.ID); err != nil {
			errJSON(w, http.StatusBadGateway, "purge data failed: %v", err)
			return
		}
	} else if app.EverContainer {
		if s.appRunner == nil {
			errJSON(w, http.StatusBadGateway, "container runner is unavailable")
			return
		}
		// Removing the public app must not orphan a stopped Docker container.
		// RemoveApp deliberately preserves the app's persistent /data;
		// purge_data=true above removes both runtime and data.
		if _, err := s.appRunner.RemoveApp(r.Context(), app.ID); err != nil {
			errJSON(w, http.StatusBadGateway, "remove runtime failed: %v", err)
			return
		}
	}
	if purgeData {
		if _, err := s.st.PurgeApp(agent.ID); err != nil {
			errJSON(w, http.StatusInternalServerError, "purge app: %v", err)
			return
		}
	} else {
		if _, err := s.st.ResetApp(agent.ID); err != nil {
			errJSON(w, http.StatusInternalServerError, "reset app: %v", err)
			return
		}
	}
	_, _ = s.st.AppendReceipt(agent.Email, "app_deleted", "", 0, s.appURL(app.Slug), "")
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted": app.Slug, "data_purged": purgeData, "identity_retained": !purgeData,
	})
}

func (s *Server) handleAppLogs(w http.ResponseWriter, r *http.Request, agent store.Agent) {
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail <= 0 {
		tail = 200
	}
	if tail > 2000 {
		tail = 2000
	}
	logs, status, err := s.appRuntimeLogs(r.Context(), agent.ID, tail)
	if errors.Is(err, store.ErrNotFound) {
		errJSON(w, http.StatusNotFound, "no container app")
		return
	}
	if err != nil {
		errJSON(w, http.StatusBadGateway, "logs failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "status": status})
}

func (s *Server) stopAppRuntime(ctx context.Context, agent store.Agent) (store.App, error) {
	app, err := s.st.AppByAgentID(agent.ID)
	if err != nil {
		return app, err
	}
	if err := s.stopAllAppRuntimes(ctx, app); err != nil {
		return app, err
	}
	return s.st.StopApp(agent.ID)
}

func (s *Server) readAppArchive(source store.File, maxExpanded int64) ([]store.AppFileSpec, error) {
	blob, err := s.st.OpenBlob(source.SHA256)
	if err != nil {
		return nil, err
	}
	defer blob.Close()
	gz, err := gzip.NewReader(blob)
	if err != nil {
		return nil, errors.New("source must be a gzip-compressed tar archive")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make([]store.AppFileSpec, 0, 64)
	seen := make(map[string]bool)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		name, err := safeAppPath(h.Name)
		if err != nil {
			return nil, err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("%q uses an unsupported archive entry type (links/devices are forbidden)", h.Name)
		}
		if name == "" {
			return nil, fmt.Errorf("empty file path")
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate path %q", name)
		}
		seen[name] = true
		if len(files) >= maxAppFiles {
			return nil, fmt.Errorf("too many files (max %d)", maxAppFiles)
		}
		if h.Size < 0 || total > maxExpanded-h.Size {
			return nil, fmt.Errorf("expanded release exceeds the remaining %d-byte app budget", maxExpanded)
		}
		if s.diskFull() {
			return nil, fmt.Errorf("%w while extracting release", store.ErrDiskReserve)
		}
		sha, size, err := s.st.PutBlob(io.LimitReader(tr, h.Size), h.Size)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if size != h.Size {
			return nil, fmt.Errorf("%s: archive declared %d bytes, read %d", name, h.Size, size)
		}
		total += size
		mt := mime.TypeByExtension(path.Ext(name))
		if mt == "" {
			mt = "application/octet-stream"
		}
		files = append(files, store.AppFileSpec{Path: name, SHA256: sha, MIME: mt, Size: size})
	}
	if len(files) == 0 {
		return nil, errors.New("archive contains no regular files")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func safeAppPath(raw string) (string, error) {
	if strings.ContainsRune(raw, '\x00') || strings.Contains(raw, "\\") || strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("unsafe archive path %q", raw)
	}
	clean := path.Clean(strings.TrimPrefix(raw, "./"))
	if clean == "." {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") || len(clean) > 1024 {
		return "", fmt.Errorf("unsafe archive path %q", raw)
	}
	if strings.Count(clean, "/") >= maxAppDepth {
		return "", fmt.Errorf("archive path is too deep: %q", raw)
	}
	return clean, nil
}

func directoryBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func (s *Server) appSlugFromHost(rawHost string) (string, bool) {
	if s.cfg.AppDomain == "" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(rawHost, "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.TrimSuffix(h, ".")
	}
	suffix := "." + s.cfg.AppDomain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	slug := strings.TrimSuffix(host, suffix)
	if slug == "" || strings.Contains(slug, ".") {
		return "", false
	}
	return slug, true
}

// managedAppHost is used by certmagic's on-demand issuance gate. Merely
// knowing an agent name cannot mint certificates: the app must be active and
// its owning agent must still have a human-email verification.
func (s *Server) managedAppHost(rawHost string) bool {
	slug, ok := s.appSlugFromHost(rawHost)
	if !ok {
		return false
	}
	app, err := s.st.AppBySlug(slug)
	if err != nil || app.Status != store.AppStatusRunning || app.ActiveDeploymentID == "" {
		return false
	}
	agent, err := s.st.AgentByID(app.AgentID)
	return err == nil && agent.HumanVerified()
}

func (s *Server) handleAppHost(w http.ResponseWriter, r *http.Request, slug string) {
	app, err := s.st.AppBySlug(slug)
	if err != nil || app.Status != store.AppStatusRunning || app.ActiveDeploymentID == "" {
		http.NotFound(w, r)
		return
	}
	agent, err := s.st.AgentByID(app.AgentID)
	if err != nil || !agent.HumanVerified() {
		http.NotFound(w, r)
		return
	}
	if app.Kind == store.AppKindContainer {
		s.proxyContainerApp(w, r, app)
		return
	}
	if app.Kind != store.AppKindStatic {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.serveStaticApp(w, r, app)
}

func (s *Server) serveStaticApp(w http.ResponseWriter, r *http.Request, app store.App) {
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || strings.HasSuffix(r.URL.Path, "/") {
		name = path.Join(name, "index.html")
	}
	f, err := s.st.AppFileByPath(app.AgentID, app.ActiveDeploymentID, name)
	if err != nil {
		deployment, derr := s.st.ActiveAppDeployment(app.AgentID)
		var cfg staticAppConfig
		if derr == nil {
			_ = json.Unmarshal(deployment.Config, &cfg)
		}
		if !cfg.SPA || path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		f, err = s.st.AppFileByPath(app.AgentID, app.ActiveDeploymentID, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	blob, err := s.st.OpenBlob(f.SHA256)
	if err != nil {
		http.Error(w, "app asset unavailable", http.StatusServiceUnavailable)
		return
	}
	defer blob.Close()
	w.Header().Set("Content-Type", f.MIME)
	w.Header().Set("ETag", `"sha256-`+f.SHA256+`"`)
	if f.Path == "index.html" || strings.HasSuffix(f.MIME, "html") {
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	http.ServeContent(w, r, path.Base(f.Path), time.Unix(app.UpdatedAt, 0), blob)
}
