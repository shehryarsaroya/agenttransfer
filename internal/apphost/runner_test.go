package apphost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testToken     = "0123456789abcdef0123456789abcdef"
	testRuntimeID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testImageID   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeDocker struct {
	path  string
	log   string
	state string
}

func newFakeDocker(t *testing.T, port int, appID, image string) fakeDocker {
	t.Helper()
	dir := t.TempDir()
	f := fakeDocker{
		path:  filepath.Join(dir, "docker"),
		log:   filepath.Join(dir, "calls.log"),
		state: filepath.Join(dir, "state"),
	}
	script := `#!/bin/sh
set -eu
printf 'CALL\n' >> "$FAKE_DOCKER_LOG"
for arg in "$@"; do
  printf 'ARG=<%s>\n' "$arg" >> "$FAKE_DOCKER_LOG"
done
command="$1"
shift
case "$command" in
  build)
    if [ "${FAKE_DOCKER_SLOW_BUILD:-}" = "1" ]; then sleep 5; fi
    : > "$FAKE_DOCKER_STATE.image"
    printf 'built image\n'
    ;;
  image)
    if [ "$1" = "inspect" ]; then
      : > "$FAKE_DOCKER_STATE.image"
      printf '[{"Config":{"Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"__APP__","com.agenttransfer.apphost.release-id":"r1"}}}]\n'
    elif [ "$1" = "ls" ]; then
      if [ -f "$FAKE_DOCKER_STATE.image" ]; then printf 'sha256:__IMAGE_ID__\n'; fi
    elif [ "$1" = "rm" ]; then
      rm -f "$FAKE_DOCKER_STATE.image"
      printf '__IMAGE__\n'
    else
      exit 2
    fi
    ;;
  pull)
    printf 'pulled %s\n' "$1"
    ;;
  run)
    printf 'running' > "$FAKE_DOCKER_STATE"
    printf '__RUNTIME__\n'
    ;;
  ps)
    if [ -f "$FAKE_DOCKER_STATE" ]; then printf '__RUNTIME__\n'; fi
    ;;
  inspect)
    if [ ! -f "$FAKE_DOCKER_STATE" ]; then
      printf 'Error: No such object: %s\n' "$1" >&2
      exit 1
    fi
    state=$(cat "$FAKE_DOCKER_STATE")
    if [ "$state" = "running" ]; then running=true; status=running; exitcode=0; else running=false; status=exited; exitcode=0; fi
    printf '[{"Id":"__RUNTIME__","Name":"/agenttransfer-app-__APP__-r1","Config":{"Image":"__IMAGE__","Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"__APP__","com.agenttransfer.apphost.release-id":"r1","com.agenttransfer.apphost.container-port":"8080"}},"State":{"Status":"%s","Running":%s,"ExitCode":%s,"StartedAt":"2026-01-01T00:00:00Z","FinishedAt":""},"NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"__PORT__"}]}}}]\n' "$status" "$running" "$exitcode"
    ;;
  port)
    printf '127.0.0.1:__PORT__\n'
    ;;
  logs)
    awk 'BEGIN { for (i=0; i<8192; i++) printf "x" }'
    ;;
  stop)
    printf 'stopped' > "$FAKE_DOCKER_STATE"
    printf '__RUNTIME__\n'
    ;;
  rm)
    rm -f "$FAKE_DOCKER_STATE"
    printf '__RUNTIME__\n'
    ;;
  *)
    printf 'unsupported fake docker command: %s\n' "$command" >&2
    exit 2
    ;;
esac
`
	script = strings.NewReplacer(
		"__APP__", appID,
		"__IMAGE__", image,
		"__PORT__", strconv.Itoa(port),
		"__RUNTIME__", testRuntimeID,
		"__IMAGE_ID__", testImageID,
	).Replace(script)
	if err := os.WriteFile(f.path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_LOG", f.log)
	t.Setenv("FAKE_DOCKER_STATE", f.state)
	return f
}

func newMultiRuntimeDocker(t *testing.T) (fakeDocker, string, string) {
	t.Helper()
	dir := t.TempDir()
	id1 := testRuntimeID
	id2 := strings.Repeat("c", 64)
	image1 := testImageID
	image2 := strings.Repeat("d", 64)
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime1", "runtime2", "image1", "image2"} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := fakeDocker{path: filepath.Join(dir, "docker"), log: filepath.Join(dir, "calls.log"), state: stateDir}
	script := `#!/bin/sh
set -eu
printf 'CALL\n' >> "$FAKE_DOCKER_LOG"
for arg in "$@"; do printf 'ARG=<%s>\n' "$arg" >> "$FAKE_DOCKER_LOG"; done
command="$1"; shift
case "$command" in
  ps)
    [ ! -f "$FAKE_DOCKER_STATE/runtime1" ] || printf '__ID1__\n'
    [ ! -f "$FAKE_DOCKER_STATE/runtime2" ] || printf '__ID2__\n'
    ;;
  inspect)
    target="$1"
    if [ "$target" = "__ID1__" ] && [ -f "$FAKE_DOCKER_STATE/runtime1" ]; then
      release=r1; image='agenttransfer-app/demo:r1'; name='agenttransfer-app-demo-r1'
    elif [ "$target" = "__ID2__" ] && [ -f "$FAKE_DOCKER_STATE/runtime2" ]; then
      release=r2; image='agenttransfer-app/demo:r2'; name='agenttransfer-app-demo-r2'
    else
      printf 'Error: No such object: %s\n' "$target" >&2; exit 1
    fi
    printf '[{"Id":"%s","Name":"/%s","Config":{"Image":"%s","Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"demo","com.agenttransfer.apphost.release-id":"%s","com.agenttransfer.apphost.container-port":"8080"}},"State":{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"","FinishedAt":""},"NetworkSettings":{"Ports":{}}}]\n' "$target" "$name" "$image" "$release"
    ;;
  rm)
	 target=""
	 for arg in "$@"; do target="$arg"; done
    if [ "$target" = "__ID1__" ]; then rm -f "$FAKE_DOCKER_STATE/runtime1"; fi
    if [ "$target" = "__ID2__" ]; then rm -f "$FAKE_DOCKER_STATE/runtime2"; fi
    printf '%s\n' "$target"
    ;;
  image)
    sub="$1"; shift
    if [ "$sub" = "ls" ]; then
      [ ! -f "$FAKE_DOCKER_STATE/image1" ] || printf 'sha256:__IMAGE1__\n'
      [ ! -f "$FAKE_DOCKER_STATE/image2" ] || printf 'sha256:__IMAGE2__\n'
    elif [ "$sub" = "rm" ]; then
      target="$1"
      if [ "$target" = "sha256:__IMAGE1__" ]; then rm -f "$FAKE_DOCKER_STATE/image1"; fi
      if [ "$target" = "sha256:__IMAGE2__" ]; then rm -f "$FAKE_DOCKER_STATE/image2"; fi
      printf '%s\n' "$target"
    else
      exit 2
    fi
    ;;
  *) exit 2 ;;
esac
`
	script = strings.NewReplacer(
		"__ID1__", id1, "__ID2__", id2,
		"__IMAGE1__", image1, "__IMAGE2__", image2,
	).Replace(script)
	if err := os.WriteFile(f.path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_LOG", f.log)
	t.Setenv("FAKE_DOCKER_STATE", f.state)
	return f, id1, id2
}

func testIDs() (uid, gid int) {
	uid, gid = os.Getuid(), os.Getgid()
	if uid == 0 {
		return containerUserID, containerUserID
	}
	if gid == 0 {
		gid = uid
	}
	return uid, gid
}

func testRunnerConfig(root, socket string, fake fakeDocker) RunnerConfig {
	uid, gid := testIDs()
	return RunnerConfig{
		AppRoot: root, SocketPath: socket, SocketMode: 0o600, AuthToken: testToken,
		DockerPath: fake.path, CommandTimeout: 2 * time.Second,
		BuildTimeout: 2 * time.Second, HealthTimeout: 2 * time.Second,
		MaxOutputBytes: 4096, MaxLogLines: 500,
		CPUCount: 0.75, MemoryBytes: 128 << 20, PIDsLimit: 64,
		TmpfsSizeBytes: 8 << 20, ContainerUID: uid, ContainerGID: gid,
	}
}

func shortSocket(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "at-runner-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func startRunner(t *testing.T, cfg RunnerConfig) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunRunner(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("runner shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runner did not stop")
		}
	})

	client, err := NewClient(ClientConfig{
		SocketPath: cfg.SocketPath, AuthToken: cfg.AuthToken,
		Timeout: 5 * time.Second, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := client.Health(context.Background()); err == nil {
			return client
		}
		if time.Now().After(deadline) {
			t.Fatal("runner never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startHealthServer(t *testing.T) (port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func materializeContext(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "contexts", "demo", "r1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunnerClientLifecycleAndDockerHardening(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	contextDir := materializeContext(t, root)
	port := startHealthServer(t)
	image := "agenttransfer-app/demo:r1"
	fake := newFakeDocker(t, port, "demo", image)
	socket := shortSocket(t)
	cfg := testRunnerConfig(root, socket, fake)
	cfg.BuildNetwork = "bridge"
	client := startRunner(t, cfg)

	wrong, err := NewClient(ClientConfig{SocketPath: socket, AuthToken: strings.Repeat("x", 32), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if err := wrong.Health(context.Background()); err == nil {
		t.Fatal("wrong runner token was accepted")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong-token error = %v", err)
		}
	}

	built, err := client.Build(context.Background(), BuildRequest{
		AppID: "demo", ReleaseID: "r1", ContextDir: contextDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if built.Image != image || !strings.Contains(built.Output, "built image") {
		t.Fatalf("build result = %+v", built)
	}

	pwned := filepath.Join(t.TempDir(), "should-not-exist")
	deployed, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: image, ContainerPort: 8080, HealthPath: "/ready",
		Env:     map[string]string{"MESSAGE": "literal;touch " + pwned},
		Command: []string{"/bin/app", "$(touch " + pwned + ")", "--serve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if deployed.RuntimeID != testRuntimeID || deployed.ReleaseID != "r1" || deployed.Upstream != fmt.Sprintf("http://127.0.0.1:%d", port) || !deployed.Healthy {
		t.Fatalf("deploy result = %+v", deployed)
	}
	if _, err := os.Stat(pwned); !os.IsNotExist(err) {
		t.Fatalf("command/env received shell interpretation: %v", err)
	}

	status, err := client.Status(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Running || status.ContainerID != testRuntimeID || status.ReleaseID != "r1" || status.URL != deployed.Upstream {
		t.Fatalf("status = %+v", status)
	}
	logs, err := client.Logs(context.Background(), "demo", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !logs.Truncated || len(logs.Output) != int(cfg.MaxOutputBytes) {
		t.Fatalf("bounded logs = len %d truncated %v", len(logs.Output), logs.Truncated)
	}
	runtimeStatus, err := client.RuntimeStatus(context.Background(), testRuntimeID)
	if err != nil || runtimeStatus.AppID != "demo" {
		t.Fatalf("runtime status = %+v, %v", runtimeStatus, err)
	}
	if runtimeLogs, err := client.RuntimeLogs(context.Background(), testRuntimeID, 50); err != nil || !runtimeLogs.Truncated {
		t.Fatalf("runtime logs = %+v, %v", runtimeLogs, err)
	}
	stopped, err := client.StopRuntime(context.Background(), testRuntimeID)
	if err != nil || !stopped.Stopped {
		t.Fatalf("stop = %+v, %v", stopped, err)
	}
	status, err = client.Status(context.Background(), "demo")
	if err != nil || status.Running || status.State != "exited" {
		t.Fatalf("stopped runtime status = %+v, %v", status, err)
	}
	removed, err := client.RemoveRuntime(context.Background(), testRuntimeID)
	if err != nil || !removed.Removed {
		t.Fatalf("remove = %+v, %v", removed, err)
	}
	status, err = client.Status(context.Background(), "demo")
	if err != nil || status.State != "stopped" || status.Running || status.ContainerID != "" {
		t.Fatalf("removed runtime app status = %+v, %v", status, err)
	}

	calls, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(calls)
	for _, want := range []string{
		"ARG=<--network>\nARG=<default>",
		"ARG=<--read-only>", "ARG=<--user>", "ARG=<--cap-drop>", "ARG=<ALL>",
		"ARG=<--pull>", "ARG=<never>",
		"ARG=<--log-driver>", "ARG=<local>", "ARG=<max-size=10m>", "ARG=<max-file=3>",
		"ARG=<--memory-swap>", "ARG=<--cpu-quota>", "ARG=<--ulimit>",
		"ARG=<--name>", "ARG=<agenttransfer-app-demo-r1>",
		"ARG=<--security-opt>", "ARG=<no-new-privileges=true>",
		"ARG=<--tmpfs>", "ARG=<--mount>", "dst=/data>",
		"ARG=<--cpus>", "ARG=<0.75>", "ARG=<--memory>\nARG=<134217728>\nARG=<--memory-swap>\nARG=<134217728>",
		"ARG=<--pids-limit>", "ARG=<64>", "ARG=<--publish>", "ARG=<127.0.0.1::8080/tcp>",
		"ARG=<--env>", "ARG=<MESSAGE=literal;touch " + pwned + ">",
	} {
		if !strings.Contains(logText, want) {
			t.Errorf("fake Docker calls missing %q\n%s", want, logText)
		}
	}
	imageAt := strings.Index(logText, "ARG=<"+image+">\nARG=</bin/app>\nARG=<$(touch "+pwned+")>\nARG=<--serve>")
	if imageAt < 0 {
		t.Errorf("container argv was not passed verbatim after image\n%s", logText)
	}
	if strings.Contains(logText, "ARG=<--privileged>") || strings.Contains(logText, "ARG=<host>") {
		t.Errorf("unsafe Docker option found\n%s", logText)
	}
	buildCall := logText
	if end := strings.Index(buildCall, "\nCALL\n"); end >= 0 {
		buildCall = buildCall[:end]
	}
	if strings.Contains(buildCall, "ARG=<--network>\nARG=<bridge>") {
		t.Errorf("BuildKit-incompatible bridge network reached docker build\n%s", logText)
	}
	firstRemove := strings.Index(logText, "CALL\nARG=<rm>")
	firstLogs := strings.Index(logText, "CALL\nARG=<logs>")
	if firstRemove < 0 || firstLogs < 0 || firstRemove < firstLogs {
		t.Errorf("runtime was removed during deploy rather than explicit RemoveRuntime\n%s", logText)
	}
	if !strings.Contains(logText, "CALL\nARG=<image>\nARG=<rm>\nARG=<"+image+">") {
		t.Errorf("managed release image was not reclaimed after StopRuntime\n%s", logText)
	}

	mode, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", mode.Mode().Perm())
	}
}

func TestFailedHealthDoesNotReturnLogsAndReclaimsManagedImage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	contextDir := materializeContext(t, root)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	})}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { _ = httpSrv.Close(); _ = ln.Close() })
	image := "agenttransfer-app/demo:r1"
	fake := newFakeDocker(t, ln.Addr().(*net.TCPAddr).Port, "demo", image)
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.HealthTimeout = 100 * time.Millisecond
	client := startRunner(t, cfg)
	if _, err := client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: contextDir}); err != nil {
		t.Fatal(err)
	}
	_, err = client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: image, ContainerPort: 8080, HealthPath: "/ready",
	})
	if err == nil || !strings.Contains(err.Error(), "health check failed") {
		t.Fatalf("health error = %v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 32)) || strings.Contains(err.Error(), "logs:") {
		t.Fatalf("health error persisted container logs: %v", err)
	}
	if _, err := os.Stat(fake.state + ".image"); !os.IsNotExist(err) {
		t.Fatalf("failed deployment image survived: %v", err)
	}
}

func TestBuildContextConfinement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	port := startHealthServer(t)
	fake := newFakeDocker(t, port, "demo", "agenttransfer-app/demo:r1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	client := startRunner(t, cfg)

	outside := materializeContext(t, filepath.Join(t.TempDir(), "outside"))
	for name, candidate := range map[string]string{"outside": outside} {
		t.Run(name, func(t *testing.T) {
			_, err := client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: candidate})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("build error = %v", err)
			}
		})
	}

	link := filepath.Join(root, "escaped")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	_, err := client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: link})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("symlink escape error = %v", err)
	}

	inside := filepath.Join(root, "inside")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(inside, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	_, err = client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: inside})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("symlink Dockerfile error = %v", err)
	}
}

func TestDeployRejectsUnsafeInputsAndDataSymlink(t *testing.T) {
	cases := []struct {
		name string
		req  DeployRequest
	}{
		{"bad app", DeployRequest{AppID: "../x", ReleaseID: "r1", Image: "agenttransfer-app/x:r1"}},
		{"flag image", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "--privileged"}},
		{"bad managed image", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/other:r1"}},
		{"bad env name", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", Env: map[string]string{"A-B": "x"}}},
		{"nul env", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", Env: map[string]string{"A": "x\x00y"}}},
		{"empty executable", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", Command: []string{""}}},
		{"bad health path", DeployRequest{AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", HealthPath: "http://elsewhere"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &runner{cfg: RunnerConfig{ImagePrefix: defaultImagePrefix}}
			if err := r.validateDeploy(tc.req); err == nil {
				t.Fatalf("accepted %+v", tc.req)
			}
		})
	}

	root := filepath.Join(t.TempDir(), "apps")
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	escape := t.TempDir()
	if err := os.Symlink(escape, filepath.Join(root, "data", "demo")); err != nil {
		t.Fatal(err)
	}
	port := startHealthServer(t)
	fake := newFakeDocker(t, port, "demo", "agenttransfer-app/demo:r1")
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))
	_, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", ContainerPort: 8080, HealthPath: "/ready",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway || !strings.Contains(apiErr.Message, "real directory") {
		t.Fatalf("data symlink error = %v", err)
	}
}

func TestRegistryImageAndPayloadBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, image := range []string{
		"alpine", "nginx:1.27-alpine", "ghcr.io/acme/widget:v1",
		"localhost:5000/team/widget@sha256:" + digest,
		"registry.example.com:5443/team/widget:release@sha256:" + digest,
	} {
		if err := validateRegistryImage(image); err != nil {
			t.Errorf("valid image %q rejected: %v", image, err)
		}
	}
	for _, image := range []string{
		"--privileged", "https://ghcr.io/a/b", "user@host/repo:tag",
		"GHCR.IO/acme/widget:v1", "localhost:99999/a", "host//repo",
		"repo:bad$tag", "repo@sha256:abcd", "repo latest",
	} {
		if err := validateRegistryImage(image); err == nil {
			t.Errorf("invalid image %q accepted", image)
		}
	}

	env := make(map[string]string, maxEnvCount+1)
	for i := 0; i <= maxEnvCount; i++ {
		env[fmt.Sprintf("K_%d", i)] = "v"
	}
	if err := validateEnv(env); err == nil {
		t.Fatal("oversized env count accepted")
	}
	if err := validateEnv(map[string]string{"BIG": strings.Repeat("x", maxEnvValueBytes+1)}); err == nil {
		t.Fatal("oversized env value accepted")
	}
	env = map[string]string{}
	for i := 0; i < 10; i++ {
		env[fmt.Sprintf("K_%d", i)] = strings.Repeat("x", 4000)
	}
	if err := validateEnv(env); err == nil {
		t.Fatal("oversized total env accepted")
	}
	command := make([]string, maxCommandArgs+1)
	for i := range command {
		command[i] = "x"
	}
	if err := validateCommand(command); err == nil {
		t.Fatal("oversized argv count accepted")
	}
	if err := validateCommand([]string{"app", strings.Repeat("x", maxCommandArgBytes+1)}); err == nil {
		t.Fatal("oversized argv value accepted")
	}
}

func TestDockerCommandTimeout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	contextDir := materializeContext(t, root)
	port := startHealthServer(t)
	fake := newFakeDocker(t, port, "demo", "agenttransfer-app/demo:r1")
	t.Setenv("FAKE_DOCKER_SLOW_BUILD", "1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.BuildTimeout = 100 * time.Millisecond
	client := startRunner(t, cfg)
	started := time.Now()
	_, err := client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: contextDir})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

func TestExternalImageIsPulledWithoutShell(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	port := startHealthServer(t)
	image := "ghcr.io/acme/widget:v1"
	fake := newFakeDocker(t, port, "demo", image)
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))
	out, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: image,
		ContainerPort: 8080, HealthPath: "/ready",
		Command: []string{"/app", "--literal=$(touch /tmp/nope)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Image != image || out.RuntimeID != testRuntimeID {
		t.Fatalf("deploy response = %+v", out)
	}
	calls, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(calls)
	if !strings.Contains(logText, "CALL\nARG=<pull>\nARG=<"+image+">") {
		t.Fatalf("external image was not explicitly pulled\n%s", logText)
	}
	if strings.Contains(logText, "CALL\nARG=<build>") {
		t.Fatalf("external image was treated as a source build\n%s", logText)
	}
	if !strings.Contains(logText, "ARG=<"+image+">\nARG=</app>\nARG=<--literal=$(touch /tmp/nope)>") {
		t.Fatalf("external image command argv ordering is wrong\n%s", logText)
	}
}

func TestStopAllAndPurgeConfinedData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	port := startHealthServer(t)
	image := "agenttransfer-app/demo:r1"
	fake := newFakeDocker(t, port, "demo", image)
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))
	if _, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: image,
		ContainerPort: 8080, HealthPath: "/ready",
	}); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "data", "demo")
	if err := os.WriteFile(filepath.Join(dataDir, "kept.db"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dataDir, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "more.bin"), []byte("1234567"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(ignored, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ignored, filepath.Join(dataDir, "ignored-link")); err != nil {
		t.Fatal(err)
	}
	status, err := client.RuntimeStatus(context.Background(), testRuntimeID)
	if err != nil || status.DataBytes != 12 {
		t.Fatalf("data byte status = %+v, %v", status, err)
	}
	outside := filepath.Join(root, "outside-marker")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopped, err := client.Stop(context.Background(), "demo")
	if err != nil || len(stopped.StoppedIDs) != 1 || stopped.StoppedIDs[0] != testRuntimeID {
		t.Fatalf("stop all = %+v, %v", stopped, err)
	}
	purged, err := client.Purge(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if purged.RemovedRuntimes != 1 || !purged.DataRemoved {
		t.Fatalf("purge = %+v", purged)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("data directory survived purge: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("purge escaped derived data path: %q, %v", data, err)
	}
}

func TestRemoveAppIsAuthenticatedIdempotentAndPreservesData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	dataDir := filepath.Join(root, "data", "demo")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dataDir, "persistent.db")
	if err := os.WriteFile(marker, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake, id1, id2 := newMultiRuntimeDocker(t)
	socket := shortSocket(t)
	client := startRunner(t, testRunnerConfig(root, socket, fake))

	wrong, err := NewClient(ClientConfig{
		SocketPath: socket, AuthToken: strings.Repeat("z", 32), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.RemoveApp(context.Background(), "demo"); err == nil {
		t.Fatal("RemoveApp accepted the wrong runner token")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong-token RemoveApp error = %v", err)
		}
	}
	var invalid RemoveAppResult
	if err := client.do(context.Background(), http.MethodPost, apiPrefix+"/apps/Bad_ID/remove", nil, &invalid); err == nil {
		t.Fatal("runner accepted invalid app id")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid-id RemoveApp error = %v", err)
		}
	}

	removed, err := client.RemoveApp(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if removed.AppID != "demo" || removed.RemovedRuntimes != 2 {
		t.Fatalf("first RemoveApp = %+v", removed)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "keep me" {
		t.Fatalf("RemoveApp changed persistent data: %q, %v", data, err)
	}
	status, err := client.Status(context.Background(), "demo")
	if err != nil || status.State != "stopped" || status.Running || status.DataBytes != int64(len("keep me")) {
		t.Fatalf("retained-data status = %+v, %v", status, err)
	}
	for _, name := range []string{"runtime1", "runtime2", "image1", "image2"} {
		if _, err := os.Stat(filepath.Join(fake.state, name)); !os.IsNotExist(err) {
			t.Errorf("fake Docker resource %s survived: %v", name, err)
		}
	}

	again, err := client.RemoveApp(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if again.AppID != "demo" || again.RemovedRuntimes != 0 {
		t.Fatalf("idempotent RemoveApp = %+v", again)
	}
	calls, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(calls)
	for _, want := range []string{
		"ARG=<rm>\nARG=<--force>\nARG=<--volumes>\nARG=<" + id1 + ">",
		"ARG=<rm>\nARG=<--force>\nARG=<--volumes>\nARG=<" + id2 + ">",
		"ARG=<image>\nARG=<rm>\nARG=<sha256:" + testImageID + ">",
		"ARG=<image>\nARG=<rm>\nARG=<sha256:" + strings.Repeat("d", 64) + ">",
	} {
		if !strings.Contains(logText, want) {
			t.Errorf("RemoveApp Docker calls missing %q\n%s", want, logText)
		}
	}
}

func TestImageVolumePolicyAllowsOnlyExplicitMountTargets(t *testing.T) {
	for _, allowed := range []map[string]json.RawMessage{
		nil,
		{"/data": json.RawMessage(`{}`)},
		{"/tmp": json.RawMessage(`{}`), "/data": json.RawMessage(`{}`)},
	} {
		if err := validateImageVolumes(allowed); err != nil {
			t.Fatalf("allowed volumes %v: %v", allowed, err)
		}
	}
	for _, denied := range []string{"/cache", "/var/lib/app", "relative", "/data/", " /tmp"} {
		if err := validateImageVolumes(map[string]json.RawMessage{denied: json.RawMessage(`{}`)}); err == nil {
			t.Fatalf("unsupported volume %q was allowed", denied)
		}
	}
}

func TestRuntimeStatusHTTPCodeDistinguishesMeasurementFromInfrastructure(t *testing.T) {
	measured := fmt.Errorf("%w: scan timed out", errDataMeasurement)
	if got := runtimeStatusHTTPCode(measured); got != http.StatusUnprocessableEntity {
		t.Fatalf("measurement error status = %d", got)
	}
	if got := runtimeStatusHTTPCode(errors.New("docker daemon unavailable")); got != http.StatusBadGateway {
		t.Fatalf("infrastructure error status = %d", got)
	}
}

func TestReconcileAppKeepsExactFullRuntimeID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	if err := os.MkdirAll(filepath.Join(root, "data", "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	fake, keepID, staleID := newMultiRuntimeDocker(t)
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))
	result, err := client.ReconcileApp(context.Background(), "demo", keepID)
	if err != nil {
		t.Fatal(err)
	}
	if result.KeptRuntimeID != keepID || result.RemovedRuntimes != 1 {
		t.Fatalf("reconcile result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(fake.state, "runtime1")); err != nil {
		t.Fatalf("desired runtime was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fake.state, "runtime2")); !os.IsNotExist(err) {
		t.Fatalf("stale runtime survived: %v", err)
	}
	logBytes, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "ARG=<ps>\nARG=<--all>\nARG=<--quiet>\nARG=<--no-trunc>") {
		t.Fatalf("runtime listing did not request full IDs:\n%s", logText)
	}
	if strings.Contains(logText, "ARG=<rm>\nARG=<--force>\nARG=<--volumes>\nARG=<"+keepID+">") ||
		!strings.Contains(logText, "ARG=<rm>\nARG=<--force>\nARG=<--volumes>\nARG=<"+staleID+">") {
		t.Fatalf("wrong runtime reconciliation:\n%s", logText)
	}
}
