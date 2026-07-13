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
	"net/url"
	"os"
	"path/filepath"
	"sort"
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

	image := strings.TrimSpace(req.Image)
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
	}

	oldRuntime := app.RuntimeID
	runtime, err := s.appRunner.Deploy(ctx, apphost.DeployRequest{
		AppID: app.ID, ReleaseID: deployment.ID, Image: image,
		ContainerPort: req.Port, HealthPath: req.HealthPath,
		Env: req.Env, Command: req.Command,
	})
	if err != nil {
		return fail(fmt.Errorf("start: %w", err))
	}
	var releaseBytes int64 = source.Size
	for _, file := range files {
		releaseBytes += file.Size
	}
	if releaseBytes+runtime.DataBytes > s.cfg.AppStorageQuota {
		_, _ = s.appRunner.RemoveRuntime(ctx, runtime.RuntimeID)
		return fail(fmt.Errorf("app uses %d bytes (release %d + persistent data %d), over quota %d",
			releaseBytes+runtime.DataBytes, releaseBytes, runtime.DataBytes, s.cfg.AppStorageQuota))
	}
	app, deployment, err = s.st.SetAppRuntime(agent.ID, deployment.ID, runtime.RuntimeID,
		runtime.Upstream, runtime.Image, req.Port, envKeys)
	if err != nil {
		_, _ = s.appRunner.RemoveRuntime(ctx, runtime.RuntimeID)
		return fail(fmt.Errorf("activate: %w", err))
	}
	// The new container is already healthy and routing now points at it. Only
	// after that atomic DB switch do we drain/remove the previous release.
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
	root, err := filepath.Abs(s.cfg.AppRoot)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "contexts", app.ID, deployment.ID)
	if rel, err := filepath.Rel(root, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("build context escaped APP_ROOT")
	}
	var required int64
	for _, file := range files {
		if file.Size < 0 || required > int64(^uint64(0)>>1)-file.Size {
			return "", errors.New("build context size overflow")
		}
		required += file.Size
	}
	if free, total, reserve := s.st.DiskStats(); reserve > 0 && total > 0 &&
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
		n, copyErr := io.CopyBuffer(&appContextWriter{s: s, dst: dst},
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
	s   *Server
	dst io.Writer
}

func (w *appContextWriter) Write(p []byte) (int, error) {
	if free, total, reserve := w.s.st.DiskStats(); reserve > 0 && total > 0 &&
		(free < reserve || int64(len(p)) > free-reserve) {
		return 0, store.ErrDiskReserve
	}
	return w.dst.Write(p)
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

func (s *Server) appRuntimeLogs(ctx context.Context, agentID string, tail int) (string, string, error) {
	app, err := s.st.AppByAgentID(agentID)
	if err != nil {
		return "", "", err
	}
	if app.Kind != store.AppKindContainer || app.RuntimeID == "" || s.appRunner == nil {
		return "", app.Status, store.ErrNotFound
	}
	logs, err := s.appRunner.RuntimeLogs(ctx, app.RuntimeID, tail)
	if err != nil {
		return "", app.Status, err
	}
	status, err := s.appRunner.RuntimeStatus(ctx, app.RuntimeID)
	if err != nil {
		return logs.Output, app.Status, nil
	}
	return logs.Output, status.State, nil
}

func (s *Server) proxyContainerApp(w http.ResponseWriter, r *http.Request, app store.App) {
	target, err := url.Parse(app.Upstream)
	if err != nil || target.Scheme != "http" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		http.Error(w, "app runtime unavailable", http.StatusBadGateway)
		return
	}
	host := target.Hostname()
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() || target.Port() == "" {
		http.Error(w, "app runtime unavailable", http.StatusBadGateway)
		return
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
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
		log.Printf("apphost: proxy %s (%s): %v", app.Slug, app.RuntimeID, err)
		http.Error(w, "app is starting or unavailable", http.StatusBadGateway)
	}
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.ServeHTTP(w, r)
}
