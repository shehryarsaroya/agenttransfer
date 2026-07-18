package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

func (s *Server) deployContainerApp(ctx context.Context, agent store.Agent, app store.App, source store.File, files []store.AppFileSpec, req appDeployRequest) (store.App, store.AppDeployment, error) {
	if s.appRunner == nil {
		return app, store.AppDeployment{}, errors.New("container hosting is unavailable; this instance supports static sites only")
	}
	if req.Port == 0 {
		req.Port = 8080
	}
	if req.Port < 1 || req.Port > 65535 {
		return app, store.AppDeployment{}, errors.New("port must be between 1 and 65535")
	}
	envKeys := make([]string, 0, len(req.Env))
	for key := range req.Env {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)
	config, _ := jsonMarshal(containerAppConfig{
		Image: strings.TrimSpace(req.Image), Port: req.Port, Command: req.Command,
		EnvKeys: envKeys, HealthPath: req.HealthPath,
	})
	deployment, err := s.st.StageContainerDeployment(agent.ID, source.SHA256, source.Size, string(config), files)
	if err != nil {
		return app, deployment, err
	}

	fail := func(cause error) (store.App, store.AppDeployment, error) {
		_ = s.st.SetAppError(agent.ID, deployment.ID, cause.Error())
		// Retain at most the newest failed/inactive attempt. A rejected build
		// must not pin an unbounded series of source blobs outside the active
		// app quota merely because the success-only pruning path was not reached.
		_, _ = s.st.PruneInactiveAppDeployments(agent.ID, 1)
		return app, deployment, cause
	}

	oldRuntime := app.RuntimeID
	oldHealthPath := "/"
	if oldRuntime != "" {
		// Validate the restoration inputs before creating a managed build image.
		// A corrupt active deployment must not leave a new release tag orphaned
		// before the runner's Deploy transaction has taken ownership of it.
		oldDeployment, err := s.st.ActiveAppDeployment(agent.ID)
		if err != nil {
			return fail(fmt.Errorf("load previous runtime config: %w", err))
		}
		var oldConfig containerAppConfig
		if err := json.Unmarshal([]byte(oldDeployment.Config), &oldConfig); err != nil || validateAppHealthPath(oldConfig.HealthPath) != nil {
			return fail(errors.New("previous runtime has an invalid health check configuration"))
		}
		oldHealthPath = oldConfig.HealthPath
	}

	image := strings.TrimSpace(req.Image)
	builtImagePending := false
	if source.ID != "" {
		contextDir, err := s.materializeAppContext(app, deployment, files)
		if err != nil {
			return fail(err)
		}
		defer os.RemoveAll(contextDir)
		built, err := s.appRunner.Build(ctx, apphost.BuildRequest{
			AppID: app.ID, ReleaseID: deployment.ID, ContextDir: contextDir,
		})
		if err != nil {
			return fail(fmt.Errorf("build: %w", err))
		}
		image = built.Image
		builtImagePending = true
	}

	oldStopped := false
	var drainErr error
	if oldRuntime != "" {
		// Every release mounts the same persistent /data directory read-write.
		// Gracefully stop the old process before starting its replacement so two
		// versions can never concurrently migrate or mutate the same state.
		// Treat any stop error as ambiguous: Docker may have stopped the process
		// even when the response was lost, so the restoration path must run.
		oldStopped = true
		if _, err := s.appRunner.StopRuntime(ctx, oldRuntime); err != nil {
			drainErr = fmt.Errorf("drain previous runtime: %w", err)
		}
	}
	cleanupBuiltImage := func(cause error) error {
		if !builtImagePending {
			return cause
		}
		// Cleanup uses only app/release IDs; the runner derives and validates the
		// reserved image reference, so the public service never sends a Docker
		// target. Use a detached timeout because the request that failed the
		// deploy may already be cancelled.
		builtImagePending = false
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := s.appRunner.RemoveImage(cleanupCtx, app.ID, deployment.ID)
		cancel()
		if cleanupErr != nil {
			return fmt.Errorf("%v; built image cleanup failed: %w", cause, cleanupErr)
		}
		return cause
	}
	restoreThenFail := func(cause error) (store.App, store.AppDeployment, error) {
		cause = cleanupBuiltImage(cause)
		if !oldStopped {
			return fail(cause)
		}
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, restoreErr := s.appRunner.ReconcileApp(restoreCtx, app.ID, oldRuntime)
		var oldStatus apphost.AppStatus
		if restoreErr == nil {
			oldStatus, restoreErr = s.appRunner.StartRuntime(restoreCtx, oldRuntime)
		}
		if restoreErr == nil {
			restoreErr = probeRuntimeHealth(restoreCtx, oldStatus.URL, oldHealthPath)
		}
		cancel()
		if restoreErr != nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = s.appRunner.Stop(stopCtx, app.ID)
			stopCancel()
			_, _ = s.st.StopApp(agent.ID)
			s.forgetRuntimeTarget(app.ID)
			cause = fmt.Errorf("%v; restoring previous runtime failed: %w", cause, restoreErr)
		} else if oldStatus.URL != app.Upstream {
			if err := s.st.RefreshAppRuntimeUpstream(agent.ID, oldRuntime, oldStatus.URL); err != nil {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, _ = s.appRunner.Stop(stopCtx, app.ID)
				stopCancel()
				_, _ = s.st.StopApp(agent.ID)
				s.forgetRuntimeTarget(app.ID)
				cause = fmt.Errorf("%v; restoring previous runtime route failed: %w", cause, err)
			} else {
				s.rememberRuntimeTarget(app.ID, oldRuntime, oldStatus.URL)
			}
		} else {
			s.rememberRuntimeTarget(app.ID, oldRuntime, oldStatus.URL)
		}
		return fail(cause)
	}
	removeThenRestore := func(runtimeID string, cause error) (store.App, store.AppDeployment, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, removeErr := s.appRunner.RemoveRuntime(cleanupCtx, runtimeID)
		cancel()
		if removeErr != nil {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = s.appRunner.Stop(stopCtx, app.ID)
			stopCancel()
			_, _ = s.st.StopApp(agent.ID)
			s.forgetRuntimeTarget(app.ID)
			return fail(fmt.Errorf("%v; replacement cleanup failed while previous runtime remains stopped: %w", cause, removeErr))
		}
		return restoreThenFail(cause)
	}
	if drainErr != nil {
		return restoreThenFail(drainErr)
	}
	runtime, err := s.appRunner.Deploy(ctx, apphost.DeployRequest{
		AppID: app.ID, ReleaseID: deployment.ID, Image: image,
		ContainerPort: req.Port, HealthPath: req.HealthPath,
		Env: req.Env, Command: req.Command,
	})
	if err != nil {
		if oldRuntime == "" {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, cleanupErr := s.appRunner.RemoveApp(cleanupCtx, app.ID)
			cancel()
			if cleanupErr != nil {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, _ = s.appRunner.Stop(stopCtx, app.ID)
				stopCancel()
				_, _ = s.st.StopApp(agent.ID)
				return fail(fmt.Errorf("start: %v; uncertain replacement cleanup failed: %w", err, cleanupErr))
			}
		}
		return restoreThenFail(fmt.Errorf("start: %w", err))
	}
	builtImagePending = false
	// A successful launch has just passed the runner's routing and HTTP health
	// gates. Reflect that proof immediately instead of leaving discovery false
	// until the short readiness cache expires.
	s.markAppRunnerReady()
	var releaseBytes int64 = source.Size
	for _, file := range files {
		var ok bool
		releaseBytes, ok = addStorageBytes(releaseBytes, file.Size)
		if !ok {
			return removeThenRestore(runtime.RuntimeID, errors.New("app release byte count is invalid or overflowing"))
		}
	}
	if !storageAdditionFits(releaseBytes, runtime.DataBytes, s.cfg.AppStorageQuota) {
		return removeThenRestore(runtime.RuntimeID, fmt.Errorf("app exceeds quota (release %d + persistent data %d; quota %d)",
			releaseBytes, runtime.DataBytes, s.cfg.AppStorageQuota))
	}
	app, deployment, err = s.st.SetAppRuntime(agent.ID, deployment.ID, runtime.RuntimeID,
		runtime.Upstream, runtime.Image, req.Port, envKeys)
	if err != nil {
		return removeThenRestore(runtime.RuntimeID, fmt.Errorf("activate: %w", err))
	}
	s.rememberRuntimeTarget(app.ID, runtime.RuntimeID, runtime.Upstream)
	// The previous release was gracefully stopped before the replacement
	// mounted shared /data. After the atomic DB switch, remove that old runtime.
	if oldRuntime != runtime.RuntimeID {
		if _, cleanupErr := s.appRunner.ReconcileApp(ctx, app.ID, runtime.RuntimeID); cleanupErr != nil {
			log.Printf("apphost: stale runtime cleanup after deploy for %s: %v", app.ID, cleanupErr)
		}
	}
	return app, deployment, nil
}

func jsonMarshal(v any) ([]byte, error) {
	// Kept as a tiny seam so deployment config serialization never includes
	// the runtime env value map by accident.
	return json.Marshal(v)
}

func (s *Server) materializeAppContext(app store.App, deployment store.AppDeployment, files []store.AppFileSpec) (string, error) {
	root, err := filepath.Abs(s.cfg.AppBuildRoot)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "contexts", app.ID, deployment.ID)
	if rel, err := filepath.Rel(root, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("build context escaped APP_BUILD_ROOT")
	}
	var required int64
	for _, file := range files {
		if file.Size < 0 || required > int64(^uint64(0)>>1)-file.Size {
			return "", errors.New("build context size overflow")
		}
		required += file.Size
	}
	if free, total, reserve := s.st.DiskStatsAt(root); reserve > 0 && total > 0 &&
		(free < reserve || required > free-reserve) {
		return "", fmt.Errorf("%w: build context needs %d bytes above the free-space floor", store.ErrDiskReserve, required)
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	cleanup := func(err error) (string, error) {
		_ = os.RemoveAll(dir)
		return "", err
	}
	for _, f := range files {
		target := filepath.Join(dir, filepath.FromSlash(f.Path))
		if rel, err := filepath.Rel(dir, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return cleanup(fmt.Errorf("unsafe build path %q", f.Path))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return cleanup(err)
		}
		src, err := s.st.OpenBlob(f.SHA256)
		if err != nil {
			return cleanup(err)
		}
		// AppFile metadata intentionally stores content, not host ownership.
		// Executable mode is safe and makes copied entrypoint scripts work in a
		// Docker build without granting any host execution to the API process.
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			src.Close()
			return cleanup(err)
		}
		n, copyErr := io.CopyBuffer(&appContextWriter{s: s, dst: dst, volumePath: root},
			io.LimitReader(src, f.Size+1), make([]byte, 1<<20))
		closeErr := dst.Close()
		src.Close()
		if copyErr != nil {
			return cleanup(copyErr)
		}
		if closeErr != nil {
			return cleanup(closeErr)
		}
		if n != f.Size {
			return cleanup(fmt.Errorf("build file %s: copied %d bytes, expected %d", f.Path, n, f.Size))
		}
	}
	return dir, nil
}

type appContextWriter struct {
	s          *Server
	dst        io.Writer
	volumePath string
}

func (w *appContextWriter) Write(p []byte) (int, error) {
	return w.s.st.WriteWithDiskReserve(w.volumePath, w.dst, p)
}

// stopAllAppRuntimes converges every runner-managed container for an app,
// including stale releases left behind by an interrupted reconciliation. The
// app-level runner operation is important here: stopping only the runtime ID
// in SQLite could leave an older container running indefinitely.
func (s *Server) stopAllAppRuntimes(ctx context.Context, app store.App) error {
	if !app.EverContainer && app.RuntimeID == "" {
		return nil
	}
	if s.appRunner == nil {
		return errors.New("container runner is unavailable")
	}
	_, err := s.appRunner.Stop(ctx, app.ID)
	var apiErr *apphost.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return nil // no managed runtime is already the desired stopped state
	}
	return err
}

func (s *Server) purgeAppData(ctx context.Context, agentID string) error {
	app, err := s.st.AppByAgentID(agentID)
	if err != nil {
		return err
	}
	if !app.EverContainer {
		return nil // static-only apps cannot own runner-managed writable data
	}
	if s.appRunner == nil {
		return errors.New("container runner is unavailable; refusing to orphan retained app data")
	}
	_, err = s.appRunner.Purge(ctx, app.ID)
	return err
}

func (s *Server) appRuntimeLogResult(ctx context.Context, agentID string, tail int) (apphost.LogsResult, string, error) {
	app, err := s.st.AppByAgentID(agentID)
	if err != nil {
		return apphost.LogsResult{}, "", err
	}
	if app.Kind != store.AppKindContainer || app.RuntimeID == "" || s.appRunner == nil {
		return apphost.LogsResult{}, app.Status, store.ErrNotFound
	}
	logs, err := s.appRunner.RuntimeLogs(ctx, app.RuntimeID, tail)
	if err != nil {
		return apphost.LogsResult{}, app.Status, err
	}
	status, err := s.appRunner.RuntimeStatus(ctx, app.RuntimeID)
	if err != nil {
		return logs, app.Status, nil
	}
	return logs, status.State, nil
}

const runtimeTargetTTL = 15 * time.Second

type runtimeTarget struct {
	runtimeID string
	upstream  string
	expires   time.Time
}

func parseRuntimeUpstream(raw string) (*url.URL, netip.Addr, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "http" || base.User != nil || base.Opaque != "" ||
		base.Path != "" || base.RawPath != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, netip.Addr{}, errors.New("invalid runtime upstream")
	}
	addr, err := netip.ParseAddr(base.Hostname())
	if err != nil {
		return nil, netip.Addr{}, errors.New("runtime upstream is not an IP address")
	}
	addr = addr.Unmap()
	port, err := strconv.Atoi(base.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, netip.Addr{}, errors.New("runtime upstream has an invalid port")
	}
	if !addr.Is4() || (!addr.IsLoopback() && !addr.IsPrivate()) || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return nil, netip.Addr{}, errors.New("runtime upstream is neither loopback nor private IPv4")
	}
	canonical := "http://" + net.JoinHostPort(addr.String(), strconv.Itoa(port))
	if raw != canonical {
		return nil, netip.Addr{}, errors.New("runtime upstream is not canonical")
	}
	return base, addr, nil
}

func (s *Server) rememberRuntimeTarget(appID, runtimeID, upstream string) {
	if appID == "" || runtimeID == "" || upstream == "" {
		return
	}
	s.appRuntimeTargets.Store(appID, runtimeTarget{
		runtimeID: runtimeID, upstream: upstream, expires: time.Now().Add(runtimeTargetTTL),
	})
}

func (s *Server) forgetRuntimeTarget(appID string) {
	s.appRuntimeTargets.Delete(appID)
}

// trustedRuntimeTarget prevents a stored upstream from becoming an SSRF
// primitive. Every target needs a fresh, exact attestation from the runner for
// this app and immutable runtime ID; private bridge targets receive the same
// treatment as loopback-published ports.
func (s *Server) trustedRuntimeTarget(ctx context.Context, app store.App) (*url.URL, error) {
	target, _, err := parseRuntimeUpstream(app.Upstream)
	if err != nil {
		return nil, err
	}
	if cached, ok := s.appRuntimeTargets.Load(app.ID); ok {
		attested, valid := cached.(runtimeTarget)
		if valid && attested.runtimeID == app.RuntimeID && attested.upstream == app.Upstream && time.Now().Before(attested.expires) {
			return target, nil
		}
	}
	if s.appRunner == nil || app.ID == "" || app.RuntimeID == "" {
		return nil, errors.New("private runtime target is not runner-attested")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	observed, err := s.appRunner.RuntimeRoute(probeCtx, app.RuntimeID)
	if err != nil {
		return nil, fmt.Errorf("attest private runtime target: %w", err)
	}
	if observed.AppID != app.ID || observed.ContainerID != app.RuntimeID || !observed.Running || observed.URL != app.Upstream {
		return nil, errors.New("stored private runtime target does not match the runner")
	}
	if _, _, err := parseRuntimeUpstream(observed.URL); err != nil {
		return nil, errors.New("runner returned an invalid runtime target")
	}
	s.rememberRuntimeTarget(app.ID, app.RuntimeID, app.Upstream)
	return target, nil
}

func probeRuntimeHealth(ctx context.Context, upstream, healthPath string) error {
	base, _, err := parseRuntimeUpstream(upstream)
	if err != nil || validateAppHealthPath(healthPath) != nil {
		return errors.New("invalid runtime health endpoint")
	}
	base.Path, base.RawPath = healthPath, ""
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
		if reqErr != nil {
			return reqErr
		}
		resp, reqErr := client.Do(req)
		if reqErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			last = fmt.Errorf("health endpoint returned %s", resp.Status)
		} else {
			last = reqErr
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return last
}

func (s *Server) proxyContainerApp(w http.ResponseWriter, r *http.Request, app store.App) {
	appSlots := s.appProxySlot(app.ID)
	select {
	case appSlots <- struct{}{}:
		defer func() { <-appSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "app proxy is at per-app capacity", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.appProxySlots <- struct{}{}:
		defer func() { <-s.appProxySlots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "app proxy is at capacity", http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > s.cfg.AppProxyBodySize {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.AppProxyBodySize)
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(s.cfg.AppProxyBodyTimeout))
		defer rc.SetReadDeadline(time.Time{})
	}
	target, err := s.trustedRuntimeTarget(r.Context(), app)
	if err != nil {
		http.Error(w, "app runtime unavailable", http.StatusBadGateway)
		return
	}
	proxy := &httputil.ReverseProxy{Transport: s.appProxyTransport, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		// Agent apps get a canonical forwarding view. Never pass client-supplied
		// Forwarded/X-Forwarded values to frameworks that may trust them.
		pr.Out.Header.Del("Forwarded")
		pr.Out.Header.Del("X-Real-Ip")
		pr.SetXForwarded()
		pr.Out.Host = pr.In.Host
		pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		pr.Out.Header.Set("X-Forwarded-For", s.clientIP(pr.In))
		proto := "http"
		if pr.In.TLS != nil {
			proto = "https"
		} else if s.cfg.BehindProxy {
			parts := strings.Split(pr.In.Header.Get("X-Forwarded-Proto"), ",")
			candidate := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
			if candidate == "http" || candidate == "https" {
				proto = candidate
			}
		}
		pr.Out.Header.Set("X-Forwarded-Proto", proto)
	}}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		log.Printf("apphost: proxy %s (%s): %v", app.Slug, app.RuntimeID, err)
		http.Error(w, "app is starting or unavailable", http.StatusBadGateway)
	}
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.ServeHTTP(w, r)
}
