package apphost

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	managedLabel       = "com.agenttransfer.apphost.managed"
	appIDLabel         = "com.agenttransfer.apphost.app-id"
	releaseIDLabel     = "com.agenttransfer.apphost.release-id"
	containerPortLabel = "com.agenttransfer.apphost.container-port"
	sourceImageLabel   = "com.agenttransfer.apphost.source-image"
	containerNameBase  = "agenttransfer-app-"
	networkNameBase    = "agenttransfer-net-"
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
	cfg             RunnerConfig
	buildRoot       string
	dataRoot        string
	snapshotRoot    string
	docker          string
	authHash        [sha256.Size]byte
	appLocks        sync.Map   // app id -> *sync.Mutex
	externalImageMu sync.Mutex // source tags are global Docker state across apps
	// internalNetworkState is 0 unproven, 1 proven host-routable, and -1
	// reserved for an engine that can be identified as unsupported without
	// conflating that platform property with one unhealthy tenant app.
	internalNetworkState atomic.Int32
	buildAdmission       chan struct{}
	buildSlot            chan struct{} // only one untrusted Dockerfile build at a time
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
	if cfg.BuildRoot == "" || strings.Contains(cfg.BuildRoot, ",") || hasControl(cfg.BuildRoot) {
		return nil, errors.New("apphost: APP_BUILD_ROOT is required")
	}
	buildRoot, err := filepath.Abs(cfg.BuildRoot)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve APP_BUILD_ROOT: %w", err)
	}
	buildRoot, err = filepath.EvalSymlinks(buildRoot)
	if err != nil {
		return nil, fmt.Errorf("apphost: resolve APP_BUILD_ROOT symlinks: %w", err)
	}
	info, err := os.Stat(buildRoot)
	if err != nil || !info.IsDir() {
		return nil, errors.New("apphost: APP_BUILD_ROOT is not a directory")
	}
	dataRoot, err := prepareOwnedRoot(cfg.DataRoot, "APP_DATA_ROOT")
	if err != nil {
		return nil, err
	}
	snapshotRoot, err := prepareOwnedRoot(cfg.SnapshotRoot, "APP_SNAPSHOT_ROOT")
	if err != nil {
		return nil, err
	}
	if rootsOverlap(buildRoot, dataRoot) || rootsOverlap(buildRoot, snapshotRoot) || rootsOverlap(dataRoot, snapshotRoot) {
		return nil, errors.New("apphost: build, data, and snapshot roots must be separate, non-nested trees")
	}
	if err := clearOwnedRoot(snapshotRoot); err != nil {
		return nil, fmt.Errorf("apphost: clear APP_SNAPSHOT_ROOT: %w", err)
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("apphost: APP_RUNNER_SOCKET is required")
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
	if len(cfg.AllowedRegistries) == 0 {
		cfg.AllowedRegistries = []string{"docker.io", "ghcr.io"}
	}
	seenRegistry := map[string]bool{}
	for i, registry := range cfg.AllowedRegistries {
		registry = strings.ToLower(strings.TrimSpace(registry))
		if registry == "" || validateRegistryHost(registry) != nil || seenRegistry[registry] {
			return nil, fmt.Errorf("apphost: invalid or duplicate allowed registry %q", registry)
		}
		seenRegistry[registry] = true
		cfg.AllowedRegistries[i] = registry
	}
	if cfg.BuildNetwork == "" {
		cfg.BuildNetwork = "none"
	}
	if cfg.BuildNetwork != "none" && cfg.BuildNetwork != "bridge" {
		return nil, errors.New("apphost: build network must be none or bridge")
	}
	if cfg.MaxBuildQueue == 0 {
		cfg.MaxBuildQueue = 8
	}
	if cfg.MaxBuildQueue < 1 || cfg.MaxBuildQueue > 64 {
		return nil, errors.New("apphost: MaxBuildQueue must be between 1 and 64")
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
	if cfg.MaxBuildContextBytes <= 0 {
		cfg.MaxBuildContextBytes = 10 << 30
	}
	if cfg.MaxBuildContextBytes > 100<<30 {
		return nil, errors.New("apphost: MaxBuildContextBytes may not exceed 100GB")
	}
	if cfg.MaxImageBytes <= 0 {
		cfg.MaxImageBytes = 10 << 30
	}
	if cfg.MaxImageBytes > 100<<30 {
		return nil, errors.New("apphost: MaxImageBytes may not exceed 100GB")
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
		cfg: cfg, buildRoot: buildRoot, dataRoot: dataRoot, snapshotRoot: snapshotRoot, docker: docker,
		authHash:       sha256.Sum256([]byte(cfg.AuthToken)),
		buildAdmission: make(chan struct{}, cfg.MaxBuildQueue),
		buildSlot:      make(chan struct{}, 1),
	}, nil
}

func prepareOwnedRoot(path, envName string) (string, error) {
	if path == "" || strings.Contains(path, ",") || hasControl(path) {
		return "", fmt.Errorf("apphost: %s is required", envName)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("apphost: resolve %s: %w", envName, err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("apphost: resolve %s parent: %w", envName, err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 || fileOwnerUID(parentInfo) != uint32(os.Geteuid()) {
		return "", fmt.Errorf("apphost: %s parent must be runner-owned and not group/world writable", envName)
	}
	canonical := filepath.Join(parent, filepath.Base(abs))
	if err := os.Mkdir(canonical, 0o700); err != nil && !os.IsExist(err) {
		return "", fmt.Errorf("apphost: create %s: %w", envName, err)
	}
	lstat, err := os.Lstat(canonical)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("apphost: %s must not be a symlink", envName)
	}
	real, err := filepath.EvalSymlinks(canonical)
	if err != nil || filepath.Clean(real) != filepath.Clean(canonical) {
		return "", fmt.Errorf("apphost: resolve %s", envName)
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || fileOwnerUID(info) != uint32(os.Geteuid()) {
		return "", fmt.Errorf("apphost: %s must be runner-owned and not group/world writable", envName)
	}
	return real, nil
}

func rootsOverlap(a, b string) bool {
	return pathWithin(a, b) || pathWithin(b, a)
}

func clearOwnedRoot(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
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
	mux.HandleFunc(apiPrefix+"/apps/{id}/images/{release}/remove", r.handleRemoveImage)
	mux.HandleFunc(apiPrefix+"/apps/{id}/reconcile", r.handleReconcileApp)
	mux.HandleFunc(apiPrefix+"/apps/{id}/purge", r.handlePurge)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/status", r.handleRuntimeStatus)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/route", r.handleRuntimeRoute)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/logs", r.handleRuntimeLogs)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/stop", r.handleRuntimeStop)
	mux.HandleFunc(apiPrefix+"/runtimes/{id}/start", r.handleRuntimeStart)
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
	result, err := r.runDocker(req.Context(), minDuration(r.cfg.CommandTimeout, 5*time.Second),
		"version", "--format", "{{.Server.Version}}")
	if err != nil || result.Truncated || strings.TrimSpace(result.Output) == "" {
		writeRunnerError(w, http.StatusServiceUnavailable, "Docker engine is unavailable")
		return
	}
	if !r.cfg.RuntimeEgress && r.internalNetworkState.Load() == 0 {
		probeCtx, cancel := context.WithTimeout(req.Context(), 750*time.Millisecond)
		r.probeExistingInternalNetwork(probeCtx)
		cancel()
	}
	state := "unknown"
	ready := r.cfg.RuntimeEgress
	if ready || r.internalNetworkState.Load() == 1 {
		state, ready = "ready", true
	} else if r.internalNetworkState.Load() == -1 {
		state = "unsupported"
	}
	writeRunnerJSON(w, http.StatusOK, healthResult{OK: true, ContainerReady: ready, ContainerState: state})
}

// probeExistingInternalNetwork restores an in-memory capability observation
// after a normal runner restart. It inspects only running, runner-labeled
// containers and trusts an endpoint only after the same network/IPAM checks
// used during deployment.
func (r *runner) probeExistingInternalNetwork(ctx context.Context) {
	result, err := r.runDocker(ctx, minDuration(r.cfg.CommandTimeout, 500*time.Millisecond),
		"ps", "--quiet", "--no-trunc", "--filter", "label="+managedLabel+"=true")
	if err != nil || result.Truncated {
		return
	}
	checked := 0
	for _, line := range strings.Split(result.Output, "\n") {
		id := strings.TrimSpace(line)
		if id == "" || validateRuntimeID(id) != nil {
			continue
		}
		checked++
		if checked > 8 || ctx.Err() != nil {
			return
		}
		status, err := r.inspectRuntimeMetadata(ctx, id, "")
		if err != nil || !status.Running || status.URL == "" {
			continue
		}
		routed, _ := probeDirectPort(ctx, status.URL, 250*time.Millisecond)
		if routed {
			r.internalNetworkState.Store(1)
			return
		}
	}
}

var errBuildQueueFull = errors.New("build queue is full")

func (r *runner) acquireBuild(ctx context.Context) (func(), error) {
	select {
	case r.buildAdmission <- struct{}{}:
	default:
		return nil, errBuildQueueFull
	}
	select {
	case r.buildSlot <- struct{}{}:
		return func() {
			<-r.buildSlot
			<-r.buildAdmission
		}, nil
	case <-ctx.Done():
		<-r.buildAdmission
		return nil, ctx.Err()
	}
}

func (r *runner) handleBuild(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	if !r.cfg.AllowSourceBuilds {
		writeRunnerError(w, http.StatusForbidden, "source container builds are disabled; deploy a digest-pinned image or explicitly trust Dockerfile builds")
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
	releaseBuild, err := r.acquireBuild(req.Context())
	if errors.Is(err, errBuildQueueFull) {
		w.Header().Set("Retry-After", "5")
		writeRunnerError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		writeRunnerError(w, http.StatusRequestTimeout, "build request was cancelled while queued")
		return
	}
	defer releaseBuild()
	mu := r.appLock(in.AppID)
	mu.Lock()
	defer mu.Unlock()
	buildContext, err := r.snapshotBuildContext(contextDir, in.AppID, in.ReleaseID)
	if err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.RemoveAll(buildContext)
	if err := r.validateDockerfileSources(filepath.Join(buildContext, "Dockerfile")); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
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
		"--tag", image, buildContext)
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

func (r *runner) handleRemoveImage(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodPost) {
		return
	}
	appID, releaseID := req.PathValue("id"), req.PathValue("release")
	if err := validateAppID(appID); err != nil {
		writeRunnerError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !releaseIDPattern.MatchString(releaseID) {
		writeRunnerError(w, http.StatusBadRequest, "invalid release_id")
		return
	}
	mu := r.appLock(appID)
	mu.Lock()
	defer mu.Unlock()
	image := r.managedImage(appID, releaseID)
	result, err := r.runDocker(req.Context(), r.cfg.CommandTimeout,
		"image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference="+image)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	if result.Truncated {
		writeRunnerError(w, http.StatusBadGateway, "docker returned too many image references")
		return
	}
	found := false
	for _, line := range strings.Split(result.Output, "\n") {
		candidate := strings.TrimSpace(line)
		if candidate == "" {
			continue
		}
		if candidate != image {
			writeRunnerError(w, http.StatusBadGateway, "docker returned an unexpected image reference")
			return
		}
		found = true
	}
	if found {
		if _, err := r.runDocker(req.Context(), r.cfg.CommandTimeout, "image", "rm", image); err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	writeRunnerJSON(w, http.StatusOK, RemoveImageResult{
		AppID: appID, ReleaseID: releaseID, Image: image, Removed: found,
	})
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

// handleRuntimeRoute is the cheap routing attestation path. Unlike status it
// does not traverse the writable /data tree, so a public proxy cache refresh
// cannot turn into attacker-triggered filesystem accounting work.
func (r *runner) handleRuntimeRoute(w http.ResponseWriter, req *http.Request) {
	if !requireMethod(w, req, http.MethodGet) {
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

func (r *runner) handleRuntimeStart(w http.ResponseWriter, req *http.Request) {
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
	status, err = r.inspectRuntimeMetadata(req.Context(), id, status.AppID)
	if err != nil {
		writeRunnerError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !status.Running {
		if _, err := r.runDocker(req.Context(), r.cfg.CommandTimeout, "start", id); err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	routeCtx, routeCancel := context.WithTimeout(req.Context(), r.cfg.CommandTimeout)
	status, err = r.waitForStartedRuntimeRoute(routeCtx, id, status.AppID)
	routeCancel()
	if err != nil || !status.Running || status.URL == "" {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "stop", "--time", "10", id)
		if err != nil {
			writeRunnerError(w, http.StatusBadGateway, err.Error())
		} else if !status.Running {
			writeRunnerError(w, http.StatusBadGateway,
				fmt.Sprintf("restarted runtime exited before routing (exit code %d)", status.ExitCode))
		} else {
			writeRunnerError(w, http.StatusBadGateway, "restarted runtime is not routable")
		}
		return
	}
	status.DataBytes, err = r.dataBytes(req.Context(), status.AppID)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "stop", "--time", "10", id)
		measureErr := fmt.Errorf("%w: %v", errDataMeasurement, err)
		writeRunnerError(w, runtimeStatusHTTPCode(measureErr), measureErr.Error())
		return
	}
	writeRunnerJSON(w, http.StatusOK, status)
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
	// Once the exact runtime is gone, reclaim only its runner-owned reference.
	// Never remove by immutable ID: one ID may also carry another app release or
	// an unrelated tag, and ID deletion can either fail or remove that reference.
	if status.Image == r.managedImage(status.AppID, status.ReleaseID) {
		_, _ = r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", status.Image)
	} else {
		r.externalImageMu.Lock()
		defer r.externalImageMu.Unlock()
		_, _ = r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", r.externalImage(status.AppID, status.ReleaseID))
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

func (r *runner) networkName(appID string) string {
	return networkNameBase + appID
}

func (r *runner) externalImage(appID, releaseID string) string {
	return r.cfg.ImagePrefix + "-external/" + appID + ":" + releaseID
}

func (r *runner) confinedBuildContext(path string) (string, error) {
	if strings.TrimSpace(path) == "" || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("context_dir is required")
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(r.buildRoot, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", errors.New("invalid context_dir")
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("context_dir is unavailable: %w", err)
	}
	if !pathWithin(r.buildRoot, real) || filepath.Clean(real) == filepath.Clean(r.buildRoot) {
		return "", errors.New("context_dir must resolve beneath APP_BUILD_ROOT")
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

// snapshotBuildContext copies a public-service-owned context into the
// runner-owned data tree through descriptor-anchored os.Root handles. Docker
// never reads the mutable public tree directly, closing both symlink and
// rename races between validation and build.
func (r *runner) snapshotBuildContext(contextDir, appID, releaseID string) (string, error) {
	rel, err := filepath.Rel(r.buildRoot, contextDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("build context escaped APP_BUILD_ROOT")
	}
	buildRoot, err := os.OpenRoot(r.buildRoot)
	if err != nil {
		return "", fmt.Errorf("open build root: %w", err)
	}
	defer buildRoot.Close()
	source, err := buildRoot.OpenRoot(filepath.ToSlash(rel))
	if err != nil {
		return "", fmt.Errorf("open confined build context: %w", err)
	}
	defer source.Close()
	sourceInfo, err := source.Stat(".")
	if err != nil || !sourceInfo.IsDir() {
		return "", errors.New("build context is not a directory")
	}
	sourceDevice := fileDevice(sourceInfo)

	snapshotRoot, err := os.OpenRoot(r.snapshotRoot)
	if err != nil {
		return "", fmt.Errorf("open snapshot root: %w", err)
	}
	defer snapshotRoot.Close()
	stageRel := filepath.ToSlash(filepath.Join(appID, releaseID))
	if err := snapshotRoot.RemoveAll(stageRel); err != nil {
		return "", fmt.Errorf("clear build snapshot: %w", err)
	}
	if err := snapshotRoot.MkdirAll(stageRel, 0o700); err != nil {
		return "", fmt.Errorf("create build snapshot: %w", err)
	}
	cleanup := func(err error) (string, error) {
		_ = snapshotRoot.RemoveAll(stageRel)
		return "", err
	}
	destination, err := snapshotRoot.OpenRoot(stageRel)
	if err != nil {
		return cleanup(fmt.Errorf("open build snapshot: %w", err))
	}
	defer destination.Close()

	const maxEntries = 100000
	entries := 0
	var total int64
	err = fs.WalkDir(source.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("build context exceeds %d entries", maxEntries)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("build context contains symlink %q", name)
		}
		info, err := source.Lstat(name)
		if err != nil {
			return err
		}
		if fileDevice(info) != sourceDevice {
			return fmt.Errorf("build context crosses a filesystem boundary at %q", name)
		}
		if info.IsDir() {
			return destination.Mkdir(name, 0o755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("build context contains non-regular file %q", name)
		}
		if info.Size() < 0 || total > r.cfg.MaxBuildContextBytes-info.Size() {
			return fmt.Errorf("build context exceeds %d bytes", r.cfg.MaxBuildContextBytes)
		}
		src, err := source.Open(name)
		if err != nil {
			return err
		}
		openedInfo, err := src.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || fileDevice(openedInfo) != sourceDevice {
			src.Close()
			return fmt.Errorf("build context file changed during snapshot: %q", name)
		}
		mode := os.FileMode(0o644)
		if openedInfo.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		dst, err := destination.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(dst, io.LimitReader(src, r.cfg.MaxBuildContextBytes-total+1))
		closeErr := dst.Close()
		src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != openedInfo.Size() || total > r.cfg.MaxBuildContextBytes-n {
			return fmt.Errorf("build context file changed size during snapshot: %q", name)
		}
		total += n
		return nil
	})
	if err != nil {
		return cleanup(fmt.Errorf("snapshot build context: %w", err))
	}
	dockerfile, err := destination.Lstat("Dockerfile")
	if err != nil || !dockerfile.Mode().IsRegular() || dockerfile.Size() > 1<<20 {
		return cleanup(errors.New("build snapshot must contain a regular Dockerfile up to 1 MiB"))
	}
	return filepath.Join(r.snapshotRoot, filepath.FromSlash(stageRel)), nil
}

func fileDevice(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev)
	}
	return ^uint64(0)
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
		if err := r.validateExternalImage(in.Image); err != nil {
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

func registryForImage(image string) string {
	name := image
	if before, _, ok := strings.Cut(name, "@"); ok {
		name = before
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		return strings.ToLower(parts[0])
	}
	return "docker.io"
}

func (r *runner) validateExternalImage(image string) error {
	if err := validateRegistryImage(image); err != nil {
		return err
	}
	if _, digest, ok := strings.Cut(image, "@"); !ok || !strings.HasPrefix(digest, "sha256:") {
		return errors.New("external images must be pinned by sha256 digest")
	}
	registry := registryForImage(image)
	for _, allowed := range r.cfg.AllowedRegistries {
		if registry == allowed {
			return nil
		}
	}
	return fmt.Errorf("registry %q is not in APP_ALLOWED_REGISTRIES", registry)
}

func (r *runner) validateDockerfileSources(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Dockerfile policy input: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat Dockerfile policy input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("Dockerfile policy input must be a regular file up to 1 MiB")
	}
	scanner := bufio.NewScanner(io.LimitReader(f, (1<<20)+1))
	scanner.Buffer(make([]byte, 64<<10), (1<<20)+1)
	stages := map[string]bool{}
	found := false
	firstLine := true
	for scanner.Scan() {
		rawLine := scanner.Text()
		if firstLine && strings.HasPrefix(rawLine, "\ufeff") {
			return errors.New("Dockerfile byte-order marks are not allowed")
		}
		firstLine = false
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "#") {
			directive := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "#")))
			key, _, hasValue := strings.Cut(directive, "=")
			switch strings.TrimSpace(key) {
			case "syntax":
				return errors.New("remote Dockerfile syntax frontends are not allowed")
			case "escape":
				if hasValue {
					return errors.New("Dockerfile escape directives are not allowed")
				}
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Source-bearing instructions are deliberately parsed as one physical
		// line. Reject continuations globally rather than letting Docker join a
		// URL, image, flag, or variable reference that this policy saw only in
		// fragments. Custom escape characters are rejected above for the same
		// reason.
		if strings.HasSuffix(line, "\\") {
			return errors.New("Dockerfile line continuations are not allowed")
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Dockerfile heredocs make subsequent physical lines data rather than
		// instructions. A lexical scanner could otherwise mistake a FROM inside
		// that data for a real stage and then allow an external COPY --from under
		// the forged alias. Strip Docker's ordinary quoting/escaping only for
		// conservative feature detection, then reject heredocs fail-closed.
		normalizedLine := strings.NewReplacer("\\", "", "\"", "", "'", "").Replace(line)
		if strings.Contains(normalizedLine, "<<") {
			return errors.New("Dockerfile heredocs are not allowed")
		}
		switch strings.ToUpper(fields[0]) {
		case "ADD":
			// ADD has remote URL and Git semantics, and Docker's lexer can hide
			// those sources behind quotes or intra-line escapes. COPY provides the
			// local-file behavior without that ambiguity.
			return errors.New("Dockerfile ADD instructions are not allowed; use COPY for local files")
		case "COPY":
			if strings.Contains(line, "$") {
				return errors.New("Dockerfile COPY variables are not allowed")
			}
			if strings.ContainsAny(line, "\\\"'") {
				return errors.New("Dockerfile COPY quoting and escaping are not allowed")
			}
			for _, field := range fields[1:] {
				lower := strings.ToLower(field)
				if !strings.HasPrefix(lower, "--from") {
					continue
				}
				from, ok := strings.CutPrefix(lower, "--from=")
				if !ok || from == "" || !stages[from] {
					return errors.New("Dockerfile COPY --from may reference only an earlier local stage")
				}
			}
		case "RUN":
			rest := strings.TrimSpace(strings.TrimPrefix(normalizedLine, fields[0]))
			if strings.HasPrefix(rest, "--") {
				// All RUN options are denied. Besides external bind sources, cache,
				// secret, and SSH mounts can persist or share data across builds, and
				// network/security/device options can weaken the build boundary.
				return errors.New("Dockerfile RUN options, including mounts, are not allowed")
			}
		case "ONBUILD":
			return errors.New("Dockerfile ONBUILD instructions are not allowed")
		case "FROM":
			if strings.ContainsAny(line, "\\\"'") {
				return errors.New("Dockerfile FROM quoting and escaping are not allowed")
			}
			rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
			if strings.HasPrefix(rest, "--") {
				return errors.New("Dockerfile FROM options are not allowed")
			}
		}
		if !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		found = true
		i := 1
		if i >= len(fields) {
			return errors.New("Dockerfile FROM is missing an image")
		}
		image := fields[i]
		if strings.Contains(image, "$") {
			return errors.New("Dockerfile FROM variables are not allowed")
		}
		if image != "scratch" && !stages[strings.ToLower(image)] {
			if err := r.validateExternalImage(image); err != nil {
				return fmt.Errorf("Dockerfile FROM %q: %w", image, err)
			}
		}
		if i+2 < len(fields) && strings.EqualFold(fields[i+1], "AS") {
			alias := strings.ToLower(fields[i+2])
			if !repositoryComponentPattern.MatchString(alias) {
				return errors.New("Dockerfile has an invalid stage alias")
			}
			stages[alias] = true
		} else if i+1 != len(fields) {
			return errors.New("Dockerfile FROM has unsupported syntax")
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Dockerfile: %w", err)
	}
	if !found {
		return errors.New("Dockerfile has no FROM instruction")
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
	var imageRow dockerImageInspect
	runtimeImage := in.Image
	externalLocked := false
	if !r.isManagedDeploy(in) {
		r.externalImageMu.Lock()
		externalLocked = true
		defer func() {
			if externalLocked {
				r.externalImageMu.Unlock()
			}
		}()
	}
	if r.isManagedDeploy(in) {
		var err error
		imageRow, err = r.inspectManagedImage(ctx, in.AppID, in.ReleaseID, in.Image)
		if err != nil {
			// Source builds use a unique, release-scoped tag. Reclaim it when
			// post-build policy validation fails (for example, an unsupported
			// Dockerfile VOLUME) just as we do after a failed container start.
			r.removeFailedImage(in)
			return DeployResponse{}, err
		}
	} else {
		if _, err := r.runDocker(ctx, r.cfg.PullTimeout, "pull", in.Image); err != nil {
			return DeployResponse{}, fmt.Errorf("pull image: %w", err)
		}
		var err error
		imageRow, err = r.inspectImageRuntimePolicy(ctx, in.Image)
		if err != nil {
			r.removeFailedImage(in)
			return DeployResponse{}, err
		}
		runtimeImage = r.externalImage(in.AppID, in.ReleaseID)
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "image", "tag", imageRow.ID, runtimeImage); err != nil {
			r.removeFailedImage(in)
			return DeployResponse{}, fmt.Errorf("pin external image: %w", err)
		}
	}
	dataDir, err := r.dataDir(in.AppID)
	if err != nil {
		r.removeFailedImage(in)
		return DeployResponse{}, err
	}
	if _, err := r.dataBytes(ctx, in.AppID); err != nil {
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("measure app data: %w", err)
	}
	name := r.containerName(in.AppID, in.ReleaseID)
	networkCreated, err := r.ensureAppNetwork(ctx, in.AppID)
	if err != nil {
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("prepare app network: %w", err)
	}
	keepNetwork := false
	defer func() {
		if networkCreated && !keepNetwork {
			_ = r.removeAppNetwork(context.Background(), in.AppID)
		}
	}()

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
		"--label", sourceImageLabel + "=" + in.Image,
		"--log-driver", "local",
		"--log-opt", "max-size=10m",
		"--log-opt", "max-file=3",
		"--network", r.networkName(in.AppID),
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
	}
	if r.cfg.RuntimeEgress {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1::%d/tcp", in.ContainerPort))
	}
	keys := make([]string, 0, len(in.Env))
	for key := range in.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+in.Env[key])
	}
	args = append(args, runtimeImage)
	args = append(args, in.Command...)
	_, err = r.runDocker(ctx, r.cfg.CommandTimeout, args...)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", name)
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("start runtime: %w", err)
	}
	startedStatus, err := r.inspectStartedRuntimeMetadata(ctx, name, in.AppID)
	if err != nil || startedStatus.ContainerID == "" || len(startedStatus.ContainerID) > 128 || hasControl(startedStatus.ContainerID) ||
		startedStatus.ImageID != imageRow.ID || startedStatus.Image != in.Image {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", name)
		r.removeFailedImage(in)
		if err != nil {
			return DeployResponse{}, fmt.Errorf("inspect started runtime: %w", err)
		}
		return DeployResponse{}, errors.New("docker returned an invalid runtime id")
	}
	runtimeID := startedStatus.ContainerID
	if !startedStatus.Running {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("container exited before health check (exit code %d)", startedStatus.ExitCode)
	}
	if !r.isManagedDeploy(in) {
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", in.Image); err != nil {
			_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
			r.removeFailedImage(in)
			return DeployResponse{}, fmt.Errorf("release external image source tag: %w", err)
		}
	}

	healthCtx, cancel := context.WithTimeout(ctx, r.cfg.HealthTimeout)
	defer cancel()
	routedStatus, err := r.waitForStartedRuntimeRoute(healthCtx, runtimeID, in.AppID)
	if err == nil && !routedStatus.Running {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("container exited before health check (exit code %d)", routedStatus.ExitCode)
	}
	upstream := routedStatus.URL
	if err == nil && !r.cfg.RuntimeEgress {
		var routed bool
		routed, err = waitForDirectPort(healthCtx, upstream)
		if routed {
			// A successful connection or an explicit refusal proves that the
			// runner host can route to this private bridge address. Keep this
			// capability separate from whether this tenant app is healthy.
			r.internalNetworkState.Store(1)
		}
		if err != nil {
			err = fmt.Errorf("internal app network address is not accepting connections; verify the app listens on port %d and, when the Docker bridge is not host-routable (including Docker Desktop), set APP_RUNTIME_EGRESS=true: %w", in.ContainerPort, err)
		}
	}
	if err == nil {
		err = waitHTTPHealthy(healthCtx, upstream+in.HealthPath)
	}
	if err != nil {
		// A process may exit after Docker assigned its route but before either
		// the TCP or HTTP probe succeeds. Prefer its concrete exit status over a
		// generic timeout while the exact managed container still exists.
		inspectCtx, inspectCancel := context.WithTimeout(context.Background(), r.cfg.CommandTimeout)
		exitStatus, inspectErr := r.inspectStartedRuntimeMetadata(inspectCtx, runtimeID, in.AppID)
		inspectCancel()
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedImage(in)
		if inspectErr == nil && !exitStatus.Running {
			return DeployResponse{}, fmt.Errorf("container exited before health check (exit code %d)", exitStatus.ExitCode)
		}
		return DeployResponse{}, fmt.Errorf("health check failed: %w", err)
	}
	// Do not give an unproven process an automatic restart loop: a bad command
	// must settle in exited state so the runner can observe its code and roll
	// back promptly. Enable restart persistence only after health succeeds.
	if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "update", "--restart", "unless-stopped", runtimeID); err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("enable runtime restart policy: %w", err)
	}
	dataBytes, err := r.dataBytes(ctx, in.AppID)
	if err != nil {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "rm", "--force", "--volumes", runtimeID)
		r.removeFailedImage(in)
		return DeployResponse{}, fmt.Errorf("measure app data after start: %w", err)
	}
	keepNetwork = true
	return DeployResponse{
		AppID: in.AppID, ReleaseID: in.ReleaseID, RuntimeID: runtimeID, ContainerName: name,
		Upstream: upstream, Image: in.Image, Healthy: true, DataBytes: dataBytes,
	}, nil
}

func (r *runner) removeFailedImage(in DeployRequest) {
	if r.isManagedDeploy(in) {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "image", "rm", in.Image)
	} else {
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "image", "rm", in.Image)
		_, _ = r.runDocker(context.Background(), r.cfg.CommandTimeout, "image", "rm", r.externalImage(in.AppID, in.ReleaseID))
	}
}

func (r *runner) dataDir(appID string) (string, error) {
	dir, err := secureSubdir(r.dataRoot, appID)
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

// waitForStartedRuntimeRoute covers the small Docker race between `run -d`
// returning and inspect publishing the container's loopback/private endpoint.
// It also observes a short-lived process exit during that window, so callers
// can report its exit code rather than an empty-IP parsing error.
func (r *runner) waitForStartedRuntimeRoute(ctx context.Context, runtimeID, appID string) (AppStatus, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := r.inspectStartedRuntimeMetadata(ctx, runtimeID, appID)
		if err != nil {
			return AppStatus{}, err
		}
		if !status.Running || status.URL != "" {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return AppStatus{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// waitForDirectPort distinguishes host routing from application readiness.
// ECONNREFUSED still proves that the private bridge address is reachable; the
// caller may safely remember that engine capability even though this app did
// not start listening before its deadline.
func waitForDirectPort(ctx context.Context, upstream string) (bool, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	routed := false
	var last error
	for {
		observed, dialErr := probeDirectPort(ctx, upstream, 500*time.Millisecond)
		routed = routed || observed
		if dialErr == nil {
			return routed, nil
		}
		last = dialErr
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return routed, last
		case <-ticker.C:
		}
	}
}

func probeDirectPort(ctx context.Context, upstream string, timeout time.Duration) (bool, error) {
	target, err := urlHostPort(upstream)
	if err != nil {
		return false, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	return errors.Is(err, syscall.ECONNREFUSED), err
}

func urlHostPort(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || u.Port() == "" {
		return "", errors.New("invalid internal runtime address")
	}
	return net.JoinHostPort(u.Hostname(), u.Port()), nil
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
	errRuntimeNotFound     = errors.New("runtime not found")
	errRuntimeRoutePending = errors.New("runtime route is not ready")
	errDataMeasurement     = errors.New("persistent data measurement failed")
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

func (r *runner) inspectManagedImage(ctx context.Context, appID, releaseID, image string) (dockerImageInspect, error) {
	row, err := r.inspectImage(ctx, image)
	if err != nil {
		return row, err
	}
	labels := row.Config.Labels
	if labels[managedLabel] != "true" || labels[appIDLabel] != appID || labels[releaseIDLabel] != releaseID {
		return row, errors.New("refusing to deploy an image not built for this app")
	}
	if err := validateImageVolumes(row.Config.Volumes); err != nil {
		return row, err
	}
	return row, nil
}

type dockerImageInspect struct {
	ID     string `json:"Id"`
	Size   int64  `json:"Size"`
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
	if !validImageID(rows[0].ID) {
		return dockerImageInspect{}, errors.New("docker image inspect returned an invalid image id")
	}
	if rows[0].Size < 0 || rows[0].Size > r.cfg.MaxImageBytes {
		return rows[0], fmt.Errorf("image size %d exceeds runner limit %d", rows[0].Size, r.cfg.MaxImageBytes)
	}
	return rows[0], nil
}

func (r *runner) inspectImageRuntimePolicy(ctx context.Context, image string) (dockerImageInspect, error) {
	row, err := r.inspectImage(ctx, image)
	if err != nil {
		return row, err
	}
	if err := validateImageVolumes(row.Config.Volumes); err != nil {
		return row, err
	}
	return row, nil
}

func validImageID(id string) bool {
	hexID, ok := strings.CutPrefix(id, "sha256:")
	return ok && len(hexID) == 64 && runtimeIDPattern.MatchString(hexID)
}

type dockerNetworkInspect struct {
	ID       string            `json:"Id"`
	Name     string            `json:"Name"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	Labels   map[string]string `json:"Labels"`
	Options  map[string]string `json:"Options"`
	IPAM     struct {
		Driver string `json:"Driver"`
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func (r *runner) ensureAppNetwork(ctx context.Context, appID string) (bool, error) {
	name := r.networkName(appID)
	created := false
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout, "network", "inspect", name)
	if err != nil {
		if !dockerNotFound(result.Output) {
			return false, err
		}
		args := []string{"network", "create", "--driver", "bridge"}
		if !r.cfg.RuntimeEgress {
			args = append(args, "--internal")
		}
		args = append(args,
			"--label", managedLabel+"=true",
			"--label", appIDLabel+"="+appID,
			"--opt", "com.docker.network.bridge.enable_icc=false", name)
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, args...); err != nil {
			return false, err
		}
		created = true
		result, err = r.runDocker(ctx, r.cfg.CommandTimeout, "network", "inspect", name)
		if err != nil {
			_ = r.removeAppNetwork(context.Background(), appID)
			return false, err
		}
	}
	var rows []dockerNetworkInspect
	if err := json.Unmarshal([]byte(result.Output), &rows); err != nil || len(rows) != 1 {
		if created {
			_ = r.removeAppNetwork(context.Background(), appID)
		}
		return false, errors.New("docker network inspect returned invalid JSON")
	}
	row := rows[0]
	if row.Name != name || row.Driver != "bridge" || row.Internal == r.cfg.RuntimeEgress || row.Labels[managedLabel] != "true" ||
		row.Labels[appIDLabel] != appID || row.Options["com.docker.network.bridge.enable_icc"] != "false" {
		if created {
			_ = r.removeAppNetwork(context.Background(), appID)
		}
		return false, errors.New("refusing to use an unlabeled or unsafe app network")
	}
	return created, nil
}

var privateIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// internalRuntimeUpstream accepts only the endpoint Docker attached to the
// exact runner-owned app network. The IP must be RFC1918 and contained by an
// RFC1918 IPAM subnet on that same network; labels or database values cannot
// steer the server proxy toward another host-local service.
func (r *runner) internalRuntimeUpstream(ctx context.Context, appID string, port int, running bool, endpoints map[string]dockerEndpointInspect) (string, string, error) {
	name := r.networkName(appID)
	endpoint, ok := endpoints[name]
	if !ok || len(endpoints) != 1 {
		if running && len(endpoints) == 0 {
			return "", "", errRuntimeRoutePending
		}
		return "", "", errors.New("container is not attached exclusively to its app network")
	}
	if running && endpoint.IPAddress == "" {
		return "", "", errRuntimeRoutePending
	}
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout, "network", "inspect", name)
	if err != nil {
		return "", "", fmt.Errorf("inspect app network endpoint: %w", err)
	}
	var rows []dockerNetworkInspect
	if err := json.Unmarshal([]byte(result.Output), &rows); err != nil || len(rows) != 1 {
		return "", "", errors.New("docker network inspect returned invalid JSON")
	}
	network := rows[0]
	if network.ID == "" || hasControl(network.ID) || endpoint.NetworkID != network.ID ||
		network.Name != name || network.Driver != "bridge" || !network.Internal ||
		network.Labels[managedLabel] != "true" || network.Labels[appIDLabel] != appID ||
		network.Options["com.docker.network.bridge.enable_icc"] != "false" {
		return "", "", errors.New("container has an unsafe or mismatched app network endpoint")
	}
	if endpoint.IPAddress == "" && !running {
		return "", "", nil
	}
	addr, err := netip.ParseAddr(endpoint.IPAddress)
	if err != nil {
		return "", "", errors.New("container app network returned an invalid IPv4 address")
	}
	addr = addr.Unmap()
	if !addr.Is4() || !addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return "", "", errors.New("container app network address is not a private IPv4 address")
	}
	contained := false
	for _, config := range network.IPAM.Config {
		subnet, parseErr := netip.ParsePrefix(config.Subnet)
		if parseErr != nil {
			continue
		}
		subnet = subnet.Masked()
		if privateIPv4Prefix(subnet) && subnet.Contains(addr) {
			contained = true
			break
		}
	}
	if !contained {
		return "", "", errors.New("container app network address is outside its private IPAM subnet")
	}
	host := addr.String()
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)), host, nil
}

func privateIPv4Prefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return false
	}
	for _, allowed := range privateIPv4Prefixes {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func (r *runner) removeAppNetwork(ctx context.Context, appID string) error {
	name := r.networkName(appID)
	result, err := r.runDocker(ctx, r.cfg.CommandTimeout, "network", "rm", name)
	if err != nil && !dockerNotFound(result.Output) {
		return err
	}
	return nil
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

type dockerEndpointInspect struct {
	NetworkID string `json:"NetworkID"`
	IPAddress string `json:"IPAddress"`
}

type dockerInspect struct {
	ID      string `json:"Id"`
	ImageID string `json:"Image"`
	Name    string `json:"Name"`
	Config  struct {
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
		Networks map[string]dockerEndpointInspect `json:"Networks"`
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
	return r.inspectRuntimeMetadataMode(ctx, target, expectedAppID, false)
}

// inspectStartedRuntimeMetadata permits a just-created container whose route
// is not published yet (or which already exited) to return its authoritative
// identity/state before route validation. Deployment then waits for either a
// validated route or an exit instead of parsing transient empty metadata.
func (r *runner) inspectStartedRuntimeMetadata(ctx context.Context, target, expectedAppID string) (AppStatus, error) {
	return r.inspectRuntimeMetadataMode(ctx, target, expectedAppID, true)
}

func (r *runner) inspectRuntimeMetadataMode(ctx context.Context, target, expectedAppID string, allowStartedWithoutRoute bool) (AppStatus, error) {
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
	sourceImage := d.Config.Labels[sourceImageLabel]
	if d.Config.Labels[managedLabel] != "true" || validateAppID(appID) != nil || !releaseIDPattern.MatchString(releaseID) ||
		(expectedAppID != "" && appID != expectedAppID) || strings.TrimPrefix(d.Name, "/") != r.containerName(appID, releaseID) {
		return AppStatus{}, errors.New("refusing to manage an unlabeled or mismatched container")
	}
	if sourceImage == r.managedImage(appID, releaseID) {
		if d.Config.Image != sourceImage {
			return AppStatus{}, errors.New("managed container image reference is inconsistent")
		}
	} else if r.validateExternalImage(sourceImage) != nil || d.Config.Image != r.externalImage(appID, releaseID) {
		return AppStatus{}, errors.New("external container image reference is inconsistent")
	}
	if !runtimeIDPattern.MatchString(d.ID) {
		return AppStatus{}, errors.New("docker inspect returned an invalid runtime id")
	}
	if !validImageID(d.ImageID) {
		return AppStatus{}, errors.New("docker inspect returned an invalid image id")
	}
	port, _ := strconv.Atoi(d.Config.Labels[containerPortLabel])
	if port < 1 || port > 65535 {
		return AppStatus{}, errors.New("container has an invalid port label")
	}
	status := AppStatus{
		AppID: appID, ReleaseID: releaseID, Image: sourceImage, ImageID: d.ImageID, ContainerID: d.ID,
		ContainerName: strings.TrimPrefix(d.Name, "/"), State: d.State.Status,
		Running: d.State.Running, ExitCode: d.State.ExitCode,
		StartedAt: d.State.StartedAt, FinishedAt: d.State.FinishedAt,
	}
	if allowStartedWithoutRoute && !status.Running {
		return status, nil
	}
	if r.cfg.RuntimeEgress {
		bindings := d.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"]
		if len(bindings) == 1 && bindings[0].HostIP == "127.0.0.1" {
			if hostPort, err := strconv.Atoi(bindings[0].HostPort); err == nil && hostPort > 0 && hostPort <= 65535 {
				status.Host, status.Port = "127.0.0.1", hostPort
				status.URL = "http://127.0.0.1:" + strconv.Itoa(hostPort)
			}
		}
		return status, nil
	}
	upstream, host, err := r.internalRuntimeUpstream(ctx, appID, port, d.State.Running, d.NetworkSettings.Networks)
	if err != nil {
		if allowStartedWithoutRoute && errors.Is(err, errRuntimeRoutePending) {
			return status, nil
		}
		return AppStatus{}, err
	}
	status.Host, status.Port, status.URL = host, port, upstream
	return status, nil
}

func (r *runner) dataBytes(ctx context.Context, appID string) (int64, error) {
	dataRoot := r.dataRoot
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
	statuses := make(map[string]AppStatus, len(ids))
	for _, runtimeID := range ids {
		status, err := r.inspectRuntimeMetadata(ctx, runtimeID, appID)
		if err != nil {
			return 0, err
		}
		statuses[runtimeID] = status
	}
	removed := 0
	for _, runtimeID := range ids {
		if err := r.removeRuntimeResource(ctx, runtimeID, statuses[runtimeID]); err != nil {
			return removed, fmt.Errorf("remove runtime %s: %w", runtimeID, err)
		}
		removed++
	}
	// Image discovery uses runner-reserved managed/external reference namespaces
	// rather than image-supplied labels. That makes retries clean up aliases left
	// by a partial call without trusting labels on an untrusted external image.
	images, err := r.listAppImageReferences(ctx, appID)
	if err != nil {
		return removed, err
	}
	for _, image := range images {
		if _, err := r.runDocker(ctx, r.cfg.CommandTimeout, "image", "rm", image); err != nil {
			return removed, fmt.Errorf("remove managed image %s: %w", image, err)
		}
	}
	if err := r.removeAppNetwork(ctx, appID); err != nil {
		return removed, fmt.Errorf("remove app network: %w", err)
	}
	return removed, nil
}

func (r *runner) listAppImageReferences(ctx context.Context, appID string) ([]string, error) {
	prefixes := []string{
		r.cfg.ImagePrefix + "/" + appID + ":",
		r.cfg.ImagePrefix + "-external/" + appID + ":",
	}
	var images []string
	seen := map[string]bool{}
	for _, prefix := range prefixes {
		result, err := r.runDocker(ctx, r.cfg.CommandTimeout,
			"image", "ls", "--format", "{{.Repository}}:{{.Tag}}", "--filter", "reference="+prefix+"*")
		if err != nil {
			return nil, err
		}
		if result.Truncated {
			return nil, errors.New("docker returned too many app images")
		}
		for _, line := range strings.Split(result.Output, "\n") {
			image := strings.TrimSpace(line)
			if image == "" {
				continue
			}
			releaseID, ok := strings.CutPrefix(image, prefix)
			if !ok || !releaseIDPattern.MatchString(releaseID) {
				return nil, errors.New("docker image ls returned an invalid app image reference")
			}
			if !seen[image] {
				seen[image] = true
				images = append(images, image)
			}
		}
	}
	return images, nil
}

func (r *runner) purgeData(appID string) (bool, error) {
	dataRoot := r.dataRoot
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
	return strings.Contains(s, "no such object") || strings.Contains(s, "no such container") ||
		strings.Contains(s, "no such network") ||
		(strings.Contains(s, "network") && strings.Contains(s, "not found"))
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
	case "build", "pull", "run", "ps", "inspect", "logs", "start", "stop", "rm", "port", "image", "network", "version":
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
