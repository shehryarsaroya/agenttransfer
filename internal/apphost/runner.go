package apphost

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	managedLabel       = "com.agenttransfer.apphost.managed"
	appIDLabel         = "com.agenttransfer.apphost.app-id"
	releaseIDLabel     = "com.agenttransfer.apphost.release-id"
	containerPortLabel = "com.agenttransfer.apphost.container-port"
	containerNameBase  = "agenttransfer-app-"
	containerUserID    = 65532
	maxRequestBytes    = 64 << 10
	maxDockerOutput    = 16 << 20
	maxEnvCount        = 64
	maxEnvValueBytes   = 4096
	maxEnvTotalBytes   = 32 << 10
	maxCommandArgs     = 64
	maxCommandArgBytes = 4096
	maxCommandBytes    = 16 << 10
)

var (
	appIDPattern               = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
	releaseIDPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	runtimeIDPattern           = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	imagePrefixPattern         = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	repositoryComponentPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	imageTagPattern            = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	envNamePattern             = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type runner struct {
	cfg      RunnerConfig
	root     string
	docker   string
	authHash [sha256.Size]byte
	appLocks sync.Map   // app id -> *sync.Mutex
	buildMu  sync.Mutex // bound host pressure: only one untrusted Dockerfile build at a time
}

// RunRunner serves the authenticated runner API on cfg.SocketPath until ctx
// is cancelled. It is deliberately the only entry point in this package that
// discovers or executes the Docker CLI.
func RunRunner(ctx context.Context, cfg RunnerConfig) error {
	r, err := newRunner(cfg)
	if err != nil {
		return err
	}
	ln, err := listenUnix(r.cfg.SocketPath, r.cfg.SocketMode, r.cfg.SocketGID)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(r.cfg.SocketPath)
	}()

	srv := &http.Server{
		Handler:           r.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		case <-stop:
		}
	}()
	err = srv.Serve(ln)
	close(stop)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func newRunner(cfg RunnerConfig) (*runner, error) {
	if cfg.AppRoot == "" || strings.Contains(cfg.AppRoot, ",") || hasControl(cfg.AppRoot) {
		return nil, errors.New("apphost: APP_ROOT is required")
	}
	root, err := filepath.Abs(cfg.AppRoot)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve APP_ROOT: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("apphost: create APP_ROOT: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve APP_ROOT symlinks: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("apphost: APP_ROOT is not a directory")
	}

	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(root, "runner.sock")
	}
	cfg.SocketPath, err = filepath.Abs(cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve socket path: %w", err)
	}
	if len(cfg.AuthToken) < 32 || len(cfg.AuthToken) > 4096 || hasControl(cfg.AuthToken) || strings.TrimSpace(cfg.AuthToken) != cfg.AuthToken {
		return nil, errors.New("apphost: runner auth token must be 32-4096 bytes")
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = 0o660
	}
	if cfg.SocketMode != 0o600 && cfg.SocketMode != 0o660 && cfg.SocketMode != 0o666 {
		return nil, errors.New("apphost: socket mode must be 0600, 0660, or 0666")
	}
	if cfg.SocketGID < 0 {
		return nil, errors.New("apphost: socket gid may not be negative")
	}
	if cfg.DockerPath == "" {
		cfg.DockerPath = "docker"
	}
	docker, err := exec.LookPath(cfg.DockerPath)
	if err != nil {
		return nil, fmt.Errorf("apphost: Docker CLI not found: %w", err)
	}
	if cfg.ImagePrefix == "" {
		cfg.ImagePrefix = defaultImagePrefix
	}
	if !imagePrefixPattern.MatchString(cfg.ImagePrefix) {
		return nil, errors.New("apphost: image prefix must be a lowercase local repository name")
	}
	if cfg.BuildNetwork == "" {
		cfg.BuildNetwork = "none"
	}
	if cfg.BuildNetwork != "none" && cfg.BuildNetwork != "bridge" {
		return nil, errors.New("apphost: build network must be none or bridge")
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.BuildTimeout <= 0 {
		cfg.BuildTimeout = 10 * time.Minute
	}
	if cfg.PullTimeout <= 0 {
		cfg.PullTimeout = 5 * time.Minute
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 30 * time.Second
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 1 << 20
	}
	if cfg.MaxOutputBytes > maxDockerOutput {
		return nil, fmt.Errorf("apphost: MaxOutputBytes may not exceed %d", maxDockerOutput)
	}
	if cfg.MaxLogLines <= 0 {
		cfg.MaxLogLines = 1000
	}
	if cfg.MaxLogLines > 10000 {
		return nil, errors.New("apphost: MaxLogLines may not exceed 10000")
	}
	if cfg.CPUCount <= 0 {
		cfg.CPUCount = 1
	}
	if cfg.MemoryBytes <= 0 {
		cfg.MemoryBytes = 512 << 20
	}
	if cfg.PIDsLimit <= 0 {
		cfg.PIDsLimit = 128
	}
	if cfg.TmpfsSizeBytes <= 0 {
		cfg.TmpfsSizeBytes = 64 << 20
	}
	if cfg.ContainerPort == 0 {
		cfg.ContainerPort = defaultContainerPort
	}
	if cfg.ContainerPort < 1 || cfg.ContainerPort > 65535 {
		return nil, errors.New("apphost: default container port is out of range")
	}
	if cfg.ContainerUID == 0 {
		cfg.ContainerUID = containerUserID
	}
	if cfg.ContainerGID == 0 {
		cfg.ContainerGID = containerUserID
	}
	if cfg.ContainerUID < 1 || cfg.ContainerGID < 1 {
		return nil, errors.New("apphost: container uid/gid must be nonzero")
	}

	return &runner{
		cfg: cfg, root: root, docker: docker,
		authHash: sha256.Sum256([]byte(cfg.AuthToken)),
	}, nil
}

func listenUnix(path string, mode os.FileMode, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("apphost: create socket directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("apphost: refusing to replace non-socket %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("apphost: runner socket %s is already active", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("apphost: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("apphost: inspect socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("apphost: listen: %w", err)
	}
	if gid > 0 {
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("apphost: set socket group: %w", err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("apphost: protect socket: %w", err)
	}
	return ln, nil
}

func (r *runner) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(apiPrefix+"/health", r.handleHealth)
	mux.HandleFunc(apiPrefix+"/build", r.handleBuild)
	mux.HandleFunc(apiPrefix+"/deploy", r.handleDeploy)
	mux.HandleFunc(apiPrefix+"/apps/{id}/status", r.handleStatus)
	mux.HandleFunc(apiPrefix+"/apps/{id}/logs", r.handleLogs)
	mux.HandleFunc(apiPrefix+"/apps/{id}/stop", r.handleStop)
	mux.HandleFunc(apiPrefix+"/apps/{id}/remove", r.handleRemoveApp)
	mux.HandleFunc(apiPrefix+"/apps/{id}/reconcile", r.handleReconcileApp)
	mux.HandleFunc(apiPrefix+"/apps/{id}/purge", r.handlePurge)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/status", r.handleRuntimeStatus)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/logs", r.handleRuntimeLogs)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/stop", r.handleRuntimeStop)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/remove", r.handleRuntimeRemove)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeRunnerError(w, http.StatusNotFound, "runner endpoint not found")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if !r.authorized(req) {
			writeRunnerError(w, http.StatusUnauthorized, "invalid runner credentials")
			return
		}
		mux.ServeHTTP(w, req)
	})
}

func (r *runner) authorized(req *http.Request) bool {
	h := req.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(got[:], r.authHash[:]) == 1
}

func requireMethod(w http.ResponseWriter, req *http.Request, method string) bool {
	if req.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeRunnerError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func (r *runner) handleHealth(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	writeRunnerJSON(w, http.StatusOK, healthResult{OK: true})
}

func (r *runner) handleBuild(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	var in BuildRequest
	if err := decodeRunnerJSON(w, req, &in); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAppID(in.AppID); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !releaseIDPattern.MatchString(in.ReleaseID) {
		writeRunnerError(w, http.StatusBadRequest, "invalid release_id")
		return
	}
	contextDir, err := r.confinedBuildContext(in.ContextDir)
	if err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	mu := r.appLock(in.AppID)
	mu.Lock()
	defer mu.Unlock()
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	image := r.managedImage(in.AppID, in.ReleaseID)
	buildNetwork := r.cfg.BuildNetwork
	if buildNetwork == "bridge" {
		// BuildKit calls its ordinary isolated/NATed build network "default";
		// "bridge" is the equivalent runtime-network term and is rejected by
		// buildx. Keep the operator-facing none|bridge contract stable while
		// translating it at the Docker boundary.
		buildNetwork = "default"
	}
	cpuQuota := int64(r.cfg.CPUCount * 100000)
	if cpuQuota < 1000 {
		cpuQuota = 1000
	}
	result, err := r.runDocker(req.Context(), r.cfg.BuildTimeout,
		"build", "--network", buildNetwork, "--pull", "--no-cache", "--force-rm",
		"--memory", strconv.FormatInt(r.cfg.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(r.cfg.MemoryBytes, 10),
		"--cpu-period", "100000", "--cpu-quota", strconv.FormatInt(cpuQuota, 10),
		"--ulimit", fmt.Sprintf("nproc=%d:%d", r.cfg.PIDsLimit, r.cfg.PIDsLimit),
		"--label", managedLabel+"=true",
		"--label", appIDLabel+"="+in.AppID,
		"--label", releaseIDLabel+"="+in.ReleaseID,
		"--tag", image, contextDir)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "image", "rm", image)
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, BuildResult{
		AppID: in.AppID, ReleaseID: in.ReleaseID, Image: image,
		Output: result.Output, OutputTruncated: result.Truncated,
	})
}

func (r *runner) handleDeploy(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	var in DeployRequest
	if err := decodeRunnerJSON(w, req, &in); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := r.validateDeploy(in); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.ContainerPort == 0 {
		in.ContainerPort = r.cfg.ContainerPort
	}
	if in.HealthPath == "" {
		in.HealthPath = "/healthz"
	}
	mu := r.appLock(in.AppID)
	mu.Lock()
	defer mu.Unlock()
	result, err := r.deploy(req.Context(), in)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, result)
}

func (r *runner) handleStatus(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	id := req.PathValue("id")
	if err := validateAppID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := r.listRuntimeIDs(req.Context(), id)
	if err == nil && len(ids) == 0 {
		dataBytes, dataErr := r.dataBytes(req.Context(), id)
		if dataErr != nil {
			measuredErr := fmt.Errorf("%w: %v", errDataMeasurement, dataErr)
			writeRunnerError(w, runtimeStatusHTTPCode(measuredErr), measuredErr.Error())
			return
		}
		writeRunnerJSON(w, http.StatusOK, AppStatus{AppID: id, State: "stopped", DataBytes: dataBytes})
		return
	}
	var status AppStatus
	if err == nil {
		status, err = r.inspectRuntime(req.Context(), ids[0], id)
	}
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "app runtime not found")
		return
	}
	if err != nil {
		writeRunnerError(w, runtimeStatusHTTPCode(err), err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, status)
}

func (r *runner) handleLogs(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	id := req.PathValue("id")
	if err := validateAppID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	lines, err := r.logTail(req)
	if err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := r.listRuntimeIDs(req.Context(), id)
	if err == nil && len(ids) == 0 {
		err = errRuntimeNotFound
	}
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "app runtime not found")
		return
	} else if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	result, err := r.runtimeLogs(req.Context(), ids[0], id, lines)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, LogsResult{
		AppID: id, Lines: lines, Output: result.Output, Truncated: result.Truncated,
	})
}

func (r *runner) handleStop(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	id := req.PathValue("id")
	if err := validateAppID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	mu := r.appLock(id)
	mu.Lock()
	defer mu.Unlock()
	ids, err := r.listRuntimeIDs(req.Context(), id)
	if err == nil && len(ids) == 0 {
		err = errRuntimeNotFound
	}
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "app runtime not found")
		return
	} else if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	stopped := make([]string, 0, len(ids))
	for _, runtimeID := range ids {
		if _, err := r.inspectRuntimeMetadata(req.Context(), runtimeID, id); err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
		if _, err := r.runDocker(req.Context(), r.cfg.CommandTimeout,
			"stop", "--time", "10", runtimeID); err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
		stopped = append(stopped, runtimeID)
	}
	writeRunnerJSON(w, http.StatusOK, StopResult{AppID: id, Stopped: true, StoppedIDs: stopped})
}

func (r *runner) handlePurge(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	id := req.PathValue("id")
	if err := validateAppID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	mu := r.appLock(id)
	mu.Lock()
	defer mu.Unlock()
	removed, err := r.removeAppResources(req.Context(), id)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	dataRemoved, err := r.purgeData(id)
	if err != nil {
		writeRunnerError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, PurgeResult{AppID: id, RemovedRuntimes: removed, DataRemoved: dataRemoved})
}

func (r *runner) handleRemoveApp(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	id := req.PathValue("id")
	if err := validateAppID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	mu := r.appLock(id)
	mu.Lock()
	defer mu.Unlock()
	removed, err := r.removeAppResources(req.Context(), id)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, RemoveAppResult{AppID: id, RemovedRuntimes: removed})
}

func (r *runner) handleReconcileApp(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	appID := req.PathValue("id")
	if err := validateAppID(appID); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	var in ReconcileRequest
	if err := decodeRunnerJSON(w, req, &in); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRuntimeID(in.KeepRuntimeID); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	mu := r.appLock(appID)
	mu.Lock()
	defer mu.Unlock()
	if _, err := r.inspectRuntimeMetadata(req.Context(), in.KeepRuntimeID, appID); err != nil {
		writeRunnerError(w, http.StatusBadGateway, "desired runtime is unavailable or does not belong to app")
		return
	}
	ids, err := r.listRuntimeIDs(req.Context(), appID)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	statuses := make(map[string]AppStatus, len(ids))
	for _, runtimeID := range ids {
		status, err := r.inspectRuntimeMetadata(req.Context(), runtimeID, appID)
		if err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
		statuses[runtimeID] = status
	}
	removed := 0
	for _, runtimeID := range ids {
		if runtimeID == in.KeepRuntimeID {
			continue
		}
		if err := r.removeRuntimeResource(req.Context(), runtimeID, statuses[runtimeID]); err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
		removed++
	}
	writeRunnerJSON(w, http.StatusOK, ReconcileResult{
		AppID: appID, KeptRuntimeID: in.KeepRuntimeID, RemovedRuntimes: removed,
	})
}

func (r *runner) handleRuntimeStatus(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	id := req.PathValue("id")
	if err := validateRuntimeID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := r.inspectRuntime(req.Context(), id, "")
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "runtime not found")
		return
	}
	if err != nil {
		writeRunnerError(w, runtimeStatusHTTPCode(err), err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, status)
}

func (r *runner) handleRuntimeLogs(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
		return
	}
	id := req.PathValue("id")
	if err := validateRuntimeID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	lines, err := r.logTail(req)
	if err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := r.inspectRuntimeMetadata(req.Context(), id, "")
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "runtime not found")
		return
	}
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	result, err := r.runtimeLogs(req.Context(), id, status.AppID, lines)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, LogsResult{AppID: status.AppID, Lines: lines, Output: result.Output, Truncated: result.Truncated})
}

func (r *runner) handleRuntimeStop(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	id := req.PathValue("id")
	if err := validateRuntimeID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := r.inspectRuntimeMetadata(req.Context(), id, "")
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "runtime not found")
		return
	}
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	mu := r.appLock(status.AppID)
	mu.Lock()
	defer mu.Unlock()
	if _, err := r.inspectRuntimeMetadata(req.Context(), id, status.AppID); err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	if _, err := r.runDocker(req.Context(), r.cfg.CommandTimeout, "stop", "--time", "10", id); err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, StopResult{AppID: status.AppID, RuntimeID: id, Stopped: true})
}

func (r *runner) handleRuntimeRemove(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	id := req.PathValue("id")
	if err := validateRuntimeID(id); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := r.inspectRuntimeMetadata(req.Context(), id, "")
	if errors.Is(err, errRuntimeNotFound) {
		writeRunnerError(w, http.StatusNotFound, "runtime not found")
		return
	}
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	mu := r.appLock(status.AppID)
	mu.Lock()
	defer mu.Unlock()
	if _, err := r.inspectRuntimeMetadata(req.Context(), id, status.AppID); err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := r.removeRuntimeResource(req.Context(), id, status); err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, RemoveResult{AppID: status.AppID, RuntimeID: id, Removed: true})
}

func (r *runner) removeRuntimeResource(ctx context.Context, runtimeID string, status AppStatus) error {
	if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID); err != nil {
		return err
	}
	// Built images are release-scoped. Once their exact runtime is gone, try
	// to reclaim the image as well; Docker safely refuses while another
	// container still references it. External registry images stay cached.
	if status.Image == r.managedImage(status.AppID, status.ReleaseID) {
		_, _ = r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", status.Image)
	}
	return nil
}

func (r *runner) logTail(req *http.Request) (int, error) {
	lines := 200
	if raw := req.URL.Query().Get("tail"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > r.cfg.MaxLogLines {
			return 0, fmt.Errorf("tail must be between 1 and %d", r.cfg.MaxLogLines)
		}
		lines = n
	}
	return lines, nil
}

func (r *runner) runtimeLogs(ctx context.Context, runtimeID, appID string, lines int) (commandResult, error) {
	if _, err := r.inspectRuntimeMetadata(ctx, runtimeID, appID); err != nil {
		return commandResult{}, err
	}
	return r.runDocker(ctx, r.cfg.CommandTimeout, "logs", "--tail", strconv.Itoa(lines), runtimeID)
}

func (r *runner) appLock(id string) *sync.Mutex {
	mu, _ := r.appLocks.LoadOrStore(id, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

func validateAppID(id string) error {
	if !appIDPattern.MatchString(id) {
		return errors.New("invalid app_id: use 1-48 lowercase letters, digits, '_' or '-', starting with a letter")
	}
	return nil
}

func validateRuntimeID(id string) error {
	if !runtimeIDPattern.MatchString(id) {
		return errors.New("invalid runtime_id")
	}
	return nil
}

func (r *runner) managedImage(appID, releaseID string) string {
	return r.cfg.ImagePrefix + "/" + appID + ":" + releaseID
}

func (r *runner) isManagedImage(appID, image string) bool {
	prefix := r.cfg.ImagePrefix + "/" + appID + ":"
	tag, ok := strings.CutPrefix(image, prefix)
	return ok && releaseIDPattern.MatchString(tag)
}

func (r *runner) containerName(appID, releaseID string) string {
	return containerNameBase + appID + "-" + releaseID
}

func (r *runner) confinedBuildContext(path string) (string, error) {
	if strings.TrimSpace(path) == "" || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("context_dir is required")
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(r.root, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", errors.New("invalid context_dir")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("context_dir is unavailable: %w", err)
	}
	if !pathWithin(r.root, real) || filepath.Clean(real) == filepath.Clean(r.root) {
		return "", errors.New("context_dir must resolve beneath APP_ROOT")
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", errors.New("context_dir is not a directory")
	}
	dockerfile := filepath.Join(real, "Dockerfile")
	df, err := os.Lstat(dockerfile)
	if err != nil || !df.Mode().IsRegular() || df.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("build context must contain a regular Dockerfile")
	}
	if df.Size() > 1<<20 {
		return "", errors.New("Dockerfile exceeds 1 MiB")
	}
	return real, nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (r *runner) validateDeploy(in DeployRequest) error {
	if err := validateAppID(in.AppID); err != nil {
		return err
	}
	if !releaseIDPattern.MatchString(in.ReleaseID) {
		return errors.New("invalid release_id")
	}
	if !r.isManagedDeploy(in) {
		if strings.HasPrefix(in.Image, r.cfg.ImagePrefix+"/") {
			return errors.New("managed image name does not match app_id and release_id")
		}
		if err := validateRegistryImage(in.Image); err != nil {
			return err
		}
	}
	if in.ContainerPort < 0 || in.ContainerPort > 65535 {
		return errors.New("container_port is out of range")
	}
	if err := validateHealthPath(in.HealthPath); err != nil {
		return err
	}
	if err := validateEnv(in.Env); err != nil {
		return err
	}
	return validateCommand(in.Command)
}

func (r *runner) isManagedDeploy(in DeployRequest) bool {
	return in.Image == r.managedImage(in.AppID, in.ReleaseID) && r.isManagedImage(in.AppID, in.Image)
}

// validateRegistryImage implements a deliberately conservative subset of the
// Docker reference grammar. It supports ordinary Docker Hub names, registry
// hosts (including ports), tags, and pinned sha256 digests while excluding
// flags, URL schemes, credentials, whitespace, and ambiguous punctuation.
func validateRegistryImage(image string) error {
	if image == "" || len(image) > 255 || hasControl(image) || strings.TrimSpace(image) != image ||
		strings.HasPrefix(image, "-") || strings.Contains(image, "://") {
		return errors.New("invalid registry image reference")
	}
	nameAndTag := image
	if before, digest, ok := strings.Cut(image, "@"); ok {
		if strings.Contains(digest, "@") || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			return errors.New("image digest must be sha256:<64 lowercase hex>")
		}
		if _, err := strconv.ParseUint(digest[len("sha256:"):len("sha256:")+16], 16, 64); err != nil {
			return errors.New("image digest must be sha256:<64 lowercase hex>")
		}
		for _, c := range digest[len("sha256:"):] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return errors.New("image digest must be sha256:<64 lowercase hex>")
			}
		}
		nameAndTag = before
	}
	lastSlash := strings.LastIndexByte(nameAndTag, '/')
	if colon := strings.LastIndexByte(nameAndTag, ':'); colon > lastSlash {
		if !imageTagPattern.MatchString(nameAndTag[colon+1:]) {
			return errors.New("invalid image tag")
		}
		nameAndTag = nameAndTag[:colon]
	}
	parts := strings.Split(nameAndTag, "/")
	if len(parts) == 0 {
		return errors.New("invalid registry image reference")
	}
	start := 0
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		if err := validateRegistryHost(parts[0]); err != nil {
			return err
		}
		start = 1
	}
	if start == len(parts) {
		return errors.New("registry image has no repository")
	}
	for _, component := range parts[start:] {
		if !repositoryComponentPattern.MatchString(component) {
			return errors.New("invalid registry repository component")
		}
	}
	return nil
}

func validateRegistryHost(hostport string) error {
	host := hostport
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		port, err := strconv.Atoi(hostport[i+1:])
		if err != nil || port < 1 || port > 65535 {
			return errors.New("invalid registry port")
		}
	}
	if host == "localhost" {
		return nil
	}
	if host == "" || len(host) > 253 {
		return errors.New("invalid registry host")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid registry host")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("invalid registry host")
			}
		}
	}
	return nil
}

func validateHealthPath(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > 256 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") || hasControl(path) {
		return errors.New("health_path must be an absolute path without query, fragment, backslash, or control characters")
	}
	return nil
}

func validateEnv(env map[string]string) error {
	if len(env) > maxEnvCount {
		return fmt.Errorf("env has more than %d entries", maxEnvCount)
	}
	total := 0
	for name, value := range env {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("invalid environment variable name %q", name)
		}
		if len(value) > maxEnvValueBytes {
			return fmt.Errorf("environment variable %s exceeds %d bytes", name, maxEnvValueBytes)
		}
		if strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("environment variable %s contains NUL", name)
		}
		total += len(name) + len(value) + 1
	}
	if total > maxEnvTotalBytes {
		return fmt.Errorf("environment exceeds %d total bytes", maxEnvTotalBytes)
	}
	return nil
}

func validateCommand(command []string) error {
	if len(command) > maxCommandArgs {
		return fmt.Errorf("command has more than %d arguments", maxCommandArgs)
	}
	total := 0
	for i, arg := range command {
		if len(arg) > maxCommandArgBytes {
			return fmt.Errorf("command argument %d exceeds %d bytes", i, maxCommandArgBytes)
		}
		if strings.IndexByte(arg, 0) >= 0 {
			return fmt.Errorf("command argument %d contains NUL", i)
		}
		total += len(arg)
	}
	if len(command) > 0 && command[0] == "" {
		return errors.New("command executable may not be empty")
	}
	if total > maxCommandBytes {
		return fmt.Errorf("command exceeds %d total bytes", maxCommandBytes)
	}
	return nil
}

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func (r *runner) deploy(ctx context.Context, in DeployRequest) (DeployResponse, error) {
	if r.isManagedDeploy(in) {
		if err := r.inspectManagedImage(ctx, in.AppID, in.ReleaseID, in.Image); err != nil {
			// Source builds use a unique, release-scoped tag. Reclaim it when
			// post-build policy validation fails (for example, an unsupported
			// Dockerfile VOLUME) just as we do after a failed container start.
			r.removeFailedManagedImage(in)
			return DeployResponse{}, err
		}
	} else {
		if _, err := r.runDocker(ctx, r.cfg.PullTimeout, "pull", in.Image); err != nil {
			return DeployResponse{}, fmt.Errorf("pull image: %w", err)
		}
		if err := r.inspectImageRuntimePolicy(ctx, in.Image); err != nil {
			return DeployResponse{}, err
		}
	}
	dataDir, err := r.dataDir(in.AppID)
	if err != nil {
		return DeployResponse{}, err
	}
	dataBytes, err := r.dataBytes(ctx, in.AppID)
	if err != nil {
		return DeployResponse{}, fmt.Errorf("measure app data: %w", err)
	}
	name := r.containerName(in.AppID, in.ReleaseID)

	user := strconv.Itoa(r.cfg.ContainerUID) + ":" + strconv.Itoa(r.cfg.ContainerGID)
	tmpfs := fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,uid=%d,gid=%d,mode=1777",
		r.cfg.TmpfsSizeBytes, r.cfg.ContainerUID, r.cfg.ContainerGID)
	args := []string{
		"run", "--detach", "--name", name,
		"--pull", "never",
		"--label", managedLabel + "=true",
		"--label", appIDLabel + "=" + in.AppID,
		"--label", releaseIDLabel + "=" + in.ReleaseID,
		"--label", containerPortLabel + "=" + strconv.Itoa(in.ContainerPort),
		"--restart", "unless-stopped",
		"--log-driver", "local",
		"--log-opt", "max-size=10m",
		"--log-opt", "max-file=3",
		"--network", "bridge",
		"--read-only",
		"--user", user,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true",
		"--tmpfs", "/tmp:" + tmpfs,
		// Bind mounts are read-write by default. Docker 29's --mount parser
		// rejects a bare trailing "rw" (boolean fields require key=value).
		"--mount", "type=bind,src=" + dataDir + ",dst=/data",
		"--cpus", strconv.FormatFloat(r.cfg.CPUCount, 'f', -1, 64),
		"--memory", strconv.FormatInt(r.cfg.MemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(r.cfg.MemoryBytes, 10),
		"--pids-limit", strconv.FormatInt(r.cfg.PIDsLimit, 10),
		"--publish", fmt.Sprintf("127.0.0.1::%d/tcp", in.ContainerPort),
	}
	keys := make([]string, 0, len(in.Env))
	for key := range in.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+in.Env[key])
	}
	args = append(args, in.Image)
	args = append(args, in.Command...)
	_, err = r.runDocker(ctx, r.cfg.CommandTimeout, args...)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", name)
		r.removeFailedManagedImage(in)
		return DeployResponse{}, fmt.Errorf("start runtime: %w", err)
	}
	startedStatus, err := r.inspectRuntimeMetadata(ctx, name, in.AppID)
	if err != nil || startedStatus.ContainerID == "" || len(startedStatus.ContainerID) > 128 || hasControl(startedStatus.ContainerID) {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", name)
		r.removeFailedManagedImage(in)
		if err != nil {
			return DeployResponse{}, fmt.Errorf("inspect started runtime: %w", err)
		}
		return DeployResponse{}, errors.New("docker returned an invalid runtime id")
	}
	runtimeID := startedStatus.ContainerID

	healthCtx, cancel := context.WithTimeout(ctx, r.cfg.HealthTimeout)
	defer cancel()
	upstream, err := r.waitForPort(healthCtx, name, in.ContainerPort)
	if err == nil {
		err = waitHTTPHealthy(healthCtx, upstream+in.HealthPath)
	}
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedManagedImage(in)
		return DeployResponse{}, fmt.Errorf("health check failed: %w", err)
	}
	dataBytes, err = r.dataBytes(ctx, in.AppID)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedManagedImage(in)
		return DeployResponse{}, fmt.Errorf("measure app data after start: %w", err)
	}
	return DeployResponse{
		AppID: in.AppID, ReleaseID: in.ReleaseID, RuntimeID: runtimeID, ContainerName: name,
		Upstream: upstream, Image: in.Image, Healthy: true, DataBytes: dataBytes,
	}, nil
}

func (r *runner) removeFailedManagedImage(in DeployRequest) {
	if r.isManagedDeploy(in) {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "image", "rm", in.Image)
	}
}

func (r *runner) dataDir(appID string) (string, error) {
	dir, err := secureSubdir(r.root, "data", appID)
	if err != nil {
		return "", fmt.Errorf("prepare app data: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("protect app data: %w", err)
	}
	if err := os.Chown(dir, r.cfg.ContainerUID, r.cfg.ContainerGID); err != nil {
		return "", fmt.Errorf("assign app data to container user: %w", err)
	}
	return dir, nil
}

func secureSubdir(root string, components ...string) (string, error) {
	current := root
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			return "", errors.New("invalid path component")
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		switch {
		case os.IsNotExist(err):
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return "", err
			}
			info, err = os.Lstat(current)
		case err != nil:
			return "", err
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("path component is not a real directory")
		}
	}
	return current, nil
}

func (r *runner) waitForPort(ctx context.Context, name string, containerPort int) (string, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := r.runDocker(ctx, minDuration(r.cfg.CommandTimeout, 5*time.Second),
			"port", name, strconv.Itoa(containerPort)+"/tcp")
		if err == nil {
			if upstream, parseErr := parseLoopbackPort(result.Output); parseErr == nil {
				return upstream, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func parseLoopbackPort(output string) (string, error) {
	line := strings.TrimSpace(strings.SplitN(output, "\n", 2)[0])
	host, portText, err := net.SplitHostPort(line)
	if err != nil || host != "127.0.0.1" {
		return "", errors.New("docker did not publish a loopback port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("docker returned an invalid host port")
	}
	return "http://127.0.0.1:" + strconv.Itoa(port), nil
}

func waitHTTPHealthy(ctx context.Context, url string) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{Proxy: nil},
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var last string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			if last == "" {
				last = ctx.Err().Error()
			}
			return errors.New(last)
		case <-ticker.C:
		}
	}
}

var (
	errRuntimeNotFound = errors.New("runtime not found")
	errDataMeasurement = errors.New("persistent data measurement failed")
)

func runtimeStatusHTTPCode(err error) int {
	if errors.Is(err, errDataMeasurement) {
		// The control plane distinguishes an authoritative measurement failure
		// (which must fail closed for quota safety) from a transient Docker or
		// runner outage (which should be retried without taking every app down).
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadGateway
}

func (r *runner) inspectManagedImage(ctx context.Context, appID, releaseID, image string) error {
	row, err := r.inspectImage(ctx, image)
	if err != nil {
		return err
	}
	labels := row.Config.Labels
	if labels[managedLabel] != "true" || labels[appIDLabel] != appID || labels[releaseIDLabel] != releaseID {
		return errors.New("refusing to deploy an image not built for this app")
	}
	return validateImageVolumes(row.Config.Volumes)
}

type dockerImageInspect struct {
	Config struct {
		Labels  map[string]string          `json:"Labels"`
		Volumes map[string]json.RawMessage `json:"Volumes"`
	} `json:"Config"`
}

func (r *runner) inspectImage(ctx context.Context, image string) (dockerImageInspect, error) {
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout, "image", "inspect", image)
	if err != nil {
		return dockerImageInspect{}, fmt.Errorf("inspect image: %w", err)
	}
	var rows []dockerImageInspect
	if err := json.Unmarshal([]byte(result.Output), &rows); err != nil || len(rows) != 1 {
		return dockerImageInspect{}, errors.New("docker image inspect returned invalid JSON")
	}
	return rows[0], nil
}

func (r *runner) inspectImageRuntimePolicy(ctx context.Context, image string) error {
	row, err := r.inspectImage(ctx, image)
	if err != nil {
		return err
	}
	return validateImageVolumes(row.Config.Volumes)
}

// Explicit mounts override image VOLUME metadata only at /data and /tmp.
// Any other declared volume would create an anonymous writable volume outside
// quota accounting despite --read-only, and could survive a redeploy.
func validateImageVolumes(volumes map[string]json.RawMessage) error {
	for volume := range volumes {
		// Require the canonical spelling. Accepting values that merely clean to
		// these paths would make the effective Docker mount target less obvious
		// and risks engine-specific parsing differences.
		if volume != "/data" && volume != "/tmp" {
			return fmt.Errorf("image declares unsupported writable volume %q; only /data and /tmp are allowed", volume)
		}
	}
	return nil
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func (r *runner) inspectRuntime(ctx context.Context, target, expectedAppID string) (AppStatus, error) {
	status, err := r.inspectRuntimeMetadata(ctx, target, expectedAppID)
	if err != nil {
		return AppStatus{}, err
	}
	status.DataBytes, err = r.dataBytes(ctx, status.AppID)
	if err != nil {
		return AppStatus{}, fmt.Errorf("%w: %v", errDataMeasurement, err)
	}
	return status, nil
}

func (r *runner) inspectRuntimeMetadata(ctx context.Context, target, expectedAppID string) (AppStatus, error) {
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout, "inspect", target)
	if err != nil {
		if dockerNotFound(result.Output) {
			return AppStatus{}, errRuntimeNotFound
		}
		return AppStatus{}, err
	}
	var rows []dockerInspect
	if err := json.Unmarshal([]byte(result.Output), &rows); err != nil || len(rows) != 1 {
		return AppStatus{}, errors.New("docker inspect returned invalid JSON")
	}
	d := rows[0]
	appID := d.Config.Labels[appIDLabel]
	releaseID := d.Config.Labels[releaseIDLabel]
	if d.Config.Labels[managedLabel] != "true" || validateAppID(appID) != nil || !releaseIDPattern.MatchString(releaseID) ||
		(expectedAppID != "" && appID != expectedAppID) || strings.TrimPrefix(d.Name, "/") != r.containerName(appID, releaseID) {
		return AppStatus{}, errors.New("refusing to manage an unlabeled or mismatched container")
	}
	if !runtimeIDPattern.MatchString(d.ID) {
		return AppStatus{}, errors.New("docker inspect returned an invalid runtime id")
	}
	port, _ := strconv.Atoi(d.Config.Labels[containerPortLabel])
	status := AppStatus{
		AppID: appID, ReleaseID: releaseID, Image: d.Config.Image, ContainerID: d.ID,
		ContainerName: strings.TrimPrefix(d.Name, "/"), State: d.State.Status,
		Running: d.State.Running, ExitCode: d.State.ExitCode,
		StartedAt: d.State.StartedAt, FinishedAt: d.State.FinishedAt,
	}
	if bindings := d.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"]; len(bindings) > 0 && bindings[0].HostIP == "127.0.0.1" {
		if hostPort, err := strconv.Atoi(bindings[0].HostPort); err == nil && hostPort > 0 && hostPort <= 65535 {
			status.Host, status.Port = "127.0.0.1", hostPort
			status.URL = "http://127.0.0.1:" + strconv.Itoa(hostPort)
		}
	}
	return status, nil
}

func (r *runner) dataBytes(ctx context.Context, appID string) (int64, error) {
	dataRoot := filepath.Join(r.root, "data")
	info, err := os.Lstat(dataRoot)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, errors.New("app data root is not a real directory")
	}
	dir := filepath.Join(dataRoot, appID)
	info, err = os.Lstat(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !pathWithin(dataRoot, dir) {
		return 0, errors.New("app data path is not a confined real directory")
	}
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	const maxEntries = 100000
	entries := 0
	var total int64
	err = filepath.WalkDir(dir, func(_ string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := scanCtx.Err(); err != nil {
			return fmt.Errorf("app data scan timed out: %w", err)
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("app data scan exceeds %d entries", maxEntries)
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			return nil
		}
		size := entryInfo.Size()
		if size < 0 || total > math.MaxInt64-size {
			return errors.New("app data byte count overflow")
		}
		total += size
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (r *runner) listRuntimeIDs(ctx context.Context, appID string) ([]string, error) {
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout,
		"ps", "--all", "--quiet", "--no-trunc",
		"--filter", "label="+managedLabel+"=true",
		"--filter", "label="+appIDLabel+"="+appID)
	if err != nil {
		return nil, err
	}
	if result.Truncated {
		return nil, errors.New("docker returned too many runtimes")
	}
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(result.Output, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if err := validateRuntimeID(id); err != nil {
			return nil, errors.New("docker ps returned an invalid runtime id")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (r *runner) removeAppResources(ctx context.Context, appID string) (int, error) {
	ids, err := r.listRuntimeIDs(ctx, appID)
	if err != nil {
		return 0, err
	}
	// Validate every target before the first destructive action. A forged or
	// stale Docker listing must never trick the runner into removing a
	// container that lacks the exact managed/app labels.
	for _, runtimeID := range ids {
		if _, err := r.inspectRuntimeMetadata(ctx, runtimeID, appID); err != nil {
			return 0, err
		}
	}
	removed := 0
	for _, runtimeID := range ids {
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID); err != nil {
			return removed, fmt.Errorf("remove runtime %s: %w", runtimeID, err)
		}
		removed++
	}
	// Image discovery is label-based rather than inferred from the runtimes.
	// That makes retries clean up an image left behind by a prior partial call,
	// even when all containers are already gone.
	images, err := r.listManagedImageIDs(ctx, appID)
	if err != nil {
		return removed, err
	}
	for _, imageID := range images {
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", imageID); err != nil {
			return removed, fmt.Errorf("remove managed image %s: %w", imageID, err)
		}
	}
	return removed, nil
}

func (r *runner) listManagedImageIDs(ctx context.Context, appID string) ([]string, error) {
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout,
		"image", "ls", "--quiet", "--no-trunc",
		"--filter", "label="+managedLabel+"=true",
		"--filter", "label="+appIDLabel+"="+appID)
	if err != nil {
		return nil, err
	}
	if result.Truncated {
		return nil, errors.New("docker returned too many managed images")
	}
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(result.Output, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		hexID := strings.TrimPrefix(id, "sha256:")
		if !runtimeIDPattern.MatchString(hexID) {
			return nil, errors.New("docker image ls returned an invalid image id")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (r *runner) purgeData(appID string) (bool, error) {
	dataRoot := filepath.Join(r.root, "data")
	info, err := os.Lstat(dataRoot)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("app data root is not a real directory")
	}
	dir := filepath.Join(dataRoot, appID)
	info, err = os.Lstat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !pathWithin(dataRoot, dir) {
		return false, errors.New("app data path is not a confined real directory")
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, fmt.Errorf("remove app data: %w", err)
	}
	return true, nil
}

func dockerNotFound(output string) bool {
	s := strings.ToLower(output)
	return strings.Contains(s, "no such object") || strings.Contains(s, "no such container")
}

type commandResult struct {
	Output    string
	Truncated bool
}

func (r *runner) runDocker(ctx context.Context, timeout time.Duration, args ...string) (commandResult, error) {
	if timeout <= 0 {
		timeout = r.cfg.CommandTimeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	buf := &boundedBuffer{limit: r.cfg.MaxOutputBytes}
	cmd := exec.CommandContext(cmdCtx, r.docker, args...)
	// Put the CLI and any helpers it starts in their own process group. Killing
	// only the top-level docker process can leave a child holding stdout open,
	// causing Cmd.Wait to outlive the advertised timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout = buf
	cmd.Stderr = buf
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1", "BUILDKIT_PROGRESS=plain")
	err := cmd.Run()
	result := commandResult{Output: buf.String(), Truncated: buf.Truncated()}
	if cmdCtx.Err() != nil {
		return result, fmt.Errorf("docker %s timed out or was cancelled: %w", dockerOperation(args), cmdCtx.Err())
	}
	if err != nil {
		out := strings.TrimSpace(result.Output)
		if out == "" {
			return result, fmt.Errorf("docker %s failed: %w", dockerOperation(args), err)
		}
		return result, fmt.Errorf("docker %s failed: %w: %s", dockerOperation(args), err, out)
	}
	return result, nil
}

func dockerOperation(args []string) string {
	if len(args) == 0 {
		return "command"
	}
	switch args[0] {
	case "build", "pull", "run", "ps", "inspect", "logs", "stop", "rm", "port", "image":
		return args[0]
	default:
		return "command"
	}
}

type boundedBuffer struct {
	mu        sync.Mutex
	data      []byte
	limit     int64
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - int64(len(b.data))
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		b.data = append(b.data, p[:int(n)]...)
	}
	if int64(len(p)) > remaining {
		b.truncated = true
	}
	return len(p), nil // keep draining the child; retained memory stays bounded
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}

func (b *boundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func decodeRunnerJSON(w http.ResponseWriter, req *http.Request, dst any) error {
	req.Body = http.MaxBytesReader(w, req.Body, maxRequestBytes)
	defer req.Body.Close()
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("invalid JSON: trailing value")
	}
	return nil
}

func writeRunnerJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeRunnerError(w http.ResponseWriter, status int, message string) {
	writeRunnerJSON(w, status, errorEnvelope{Error: message})
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
