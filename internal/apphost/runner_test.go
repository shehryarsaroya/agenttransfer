package apphost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	runtimeImage := image
	if image != defaultImagePrefix+"/"+appID+":r1" {
		runtimeImage = defaultImagePrefix + "-external/" + appID + ":r1"
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
  version)
    if [ "${FAKE_DOCKER_UNHEALTHY:-}" = "1" ]; then exit 1; fi
    printf '29.0.0\n'
    ;;
  build)
    if [ "${FAKE_DOCKER_SLOW_BUILD:-}" = "1" ]; then sleep 5; fi
    : > "$FAKE_DOCKER_STATE.image"
    printf 'built image\n'
    ;;
  image)
    if [ "$1" = "inspect" ]; then
      : > "$FAKE_DOCKER_STATE.image"
      printf '[{"Id":"sha256:__IMAGE_ID__","Config":{"Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"__APP__","com.agenttransfer.apphost.release-id":"r1"}}}]\n'
    elif [ "$1" = "ls" ]; then
      if [ -f "$FAKE_DOCKER_STATE.image" ]; then
        for arg in "$@"; do
          case "$arg" in
            reference=*)
              pattern=${arg#reference=}
              case '__RUNTIME_IMAGE__' in $pattern) printf '__RUNTIME_IMAGE__\n';; esac
              ;;
          esac
        done
      fi
    elif [ "$1" = "rm" ]; then
      rm -f "$FAKE_DOCKER_STATE.image"
      printf '__IMAGE__\n'
    elif [ "$1" = "tag" ]; then
      : > "$FAKE_DOCKER_STATE.image"
      printf '__RUNTIME_IMAGE__\n'
    else
      exit 2
    fi
    ;;
  pull)
    printf 'pulled %s\n' "$1"
    ;;
  network)
    sub="$1"; shift
    if [ "$sub" = "inspect" ]; then
      if [ ! -f "$FAKE_DOCKER_STATE.network" ]; then
        printf 'Error response from daemon: network %s not found\n' "$1" >&2
        exit 1
      fi
      printf '[{"Id":"network-id","Name":"agenttransfer-net-__APP__","Driver":"bridge","Internal":%s,"Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"__APP__"},"Options":{"com.docker.network.bridge.enable_icc":"false"},"IPAM":{"Driver":"default","Config":[{"Subnet":"%s"}]}}]\n' "${FAKE_DOCKER_INTERNAL:-false}" "${FAKE_DOCKER_SUBNET:-172.18.0.0/16}"
    elif [ "$sub" = "create" ]; then
      : > "$FAKE_DOCKER_STATE.network"
      printf 'network-id\n'
    elif [ "$sub" = "rm" ]; then
      if [ ! -f "$FAKE_DOCKER_STATE.network" ]; then
        printf 'Error response from daemon: network %s not found\n' "$1" >&2
        exit 1
      fi
      rm -f "$FAKE_DOCKER_STATE.network"
      printf '%s\n' "$1"
    else
      exit 2
    fi
    ;;
  run)
	rm -f "$FAKE_DOCKER_STATE.inspected"
	if [ "${FAKE_DOCKER_EXIT_IMMEDIATELY:-}" = "1" ]; then
	  printf 'exited' > "$FAKE_DOCKER_STATE"
	else
	  printf 'running' > "$FAKE_DOCKER_STATE"
	fi
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
	if [ "$state" = "running" ]; then running=true; status=running; exitcode=0; else running=false; status=exited; exitcode="${FAKE_DOCKER_EXIT_CODE:-0}"; fi
	endpoint_ip="${FAKE_DOCKER_IP:-172.18.0.2}"
	if [ "$running" = "true" ] && [ "${FAKE_DOCKER_EMPTY_IP_ALWAYS:-}" = "1" ]; then
	  endpoint_ip=''
	elif [ "$running" = "true" ] && [ "${FAKE_DOCKER_EMPTY_IP_ONCE:-}" = "1" ] && [ ! -f "$FAKE_DOCKER_STATE.inspected" ]; then
	  : > "$FAKE_DOCKER_STATE.inspected"
	  endpoint_ip=''
	elif [ "$running" = "true" ] && [ "${FAKE_DOCKER_EMPTY_IP_THEN_EXIT:-}" = "1" ] && [ ! -f "$FAKE_DOCKER_STATE.inspected" ]; then
	  : > "$FAKE_DOCKER_STATE.inspected"
	  endpoint_ip=''
	  printf 'exited' > "$FAKE_DOCKER_STATE"
	fi
	if [ "$running" = "false" ] && [ "${FAKE_DOCKER_CLEAR_IP_WHEN_STOPPED:-}" = "1" ]; then endpoint_ip=''; fi
	networks='{"agenttransfer-net-__APP__":{"NetworkID":"network-id","IPAddress":"'"$endpoint_ip"'"}}'
	if [ "$running" = "false" ] && [ "${FAKE_DOCKER_CLEAR_NETWORK_WHEN_STOPPED:-}" = "1" ]; then networks='{}'; fi
    if [ "${FAKE_DOCKER_INTERNAL:-false}" = "true" ]; then
      ports='{}'
    else
      ports='{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"__PORT__"}]}'
    fi
    printf '[{"Id":"__RUNTIME__","Image":"sha256:__IMAGE_ID__","Name":"/agenttransfer-app-__APP__-r1","Config":{"Image":"__RUNTIME_IMAGE__","Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"__APP__","com.agenttransfer.apphost.release-id":"r1","com.agenttransfer.apphost.container-port":"%s","com.agenttransfer.apphost.source-image":"__IMAGE__"}},"State":{"Status":"%s","Running":%s,"ExitCode":%s,"StartedAt":"2026-01-01T00:00:00Z","FinishedAt":""},"NetworkSettings":{"Ports":%s,"Networks":%s}}]\n' "${FAKE_DOCKER_CONTAINER_PORT:-8080}" "$status" "$running" "$exitcode" "$ports" "$networks"
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
  start)
	rm -f "$FAKE_DOCKER_STATE.inspected"
    printf 'running' > "$FAKE_DOCKER_STATE"
    printf '__RUNTIME__\n'
    ;;
  update)
    printf '__RUNTIME__\n'
    ;;
  rm)
	rm -f "$FAKE_DOCKER_STATE" "$FAKE_DOCKER_STATE.inspected"
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
		"__RUNTIME_IMAGE__", runtimeImage,
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
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime1", "runtime2", "image1", "image2", "orphan", "unrelated"} {
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
  version)
    printf '29.0.0\n'
    ;;
  ps)
    [ ! -f "$FAKE_DOCKER_STATE/runtime1" ] || printf '__ID1__\n'
    [ ! -f "$FAKE_DOCKER_STATE/runtime2" ] || printf '__ID2__\n'
    ;;
  inspect)
    target="$1"
    if [ "$target" = "__ID1__" ] && [ -f "$FAKE_DOCKER_STATE/runtime1" ]; then
      release=r1; image='agenttransfer-app/demo:r1'; image_id='sha256:__IMAGE1__'; name='agenttransfer-app-demo-r1'
    elif [ "$target" = "__ID2__" ] && [ -f "$FAKE_DOCKER_STATE/runtime2" ]; then
      release=r2; image='agenttransfer-app/demo:r2'; image_id='sha256:__IMAGE1__'; name='agenttransfer-app-demo-r2'
    else
      printf 'Error: No such object: %s\n' "$target" >&2; exit 1
    fi
    printf '[{"Id":"%s","Image":"%s","Name":"/%s","Config":{"Image":"%s","Labels":{"com.agenttransfer.apphost.managed":"true","com.agenttransfer.apphost.app-id":"demo","com.agenttransfer.apphost.release-id":"%s","com.agenttransfer.apphost.container-port":"8080","com.agenttransfer.apphost.source-image":"%s"}},"State":{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"","FinishedAt":""},"NetworkSettings":{"Ports":{}}}]\n' "$target" "$image_id" "$name" "$image" "$release" "$image"
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
      reference=''
      for arg in "$@"; do case "$arg" in reference=*) reference=${arg#reference=};; esac; done
      if [ "$reference" = 'agenttransfer-app/demo:*' ]; then
        [ ! -f "$FAKE_DOCKER_STATE/image1" ] || printf 'agenttransfer-app/demo:r1\n'
        [ ! -f "$FAKE_DOCKER_STATE/image2" ] || printf 'agenttransfer-app/demo:r2\n'
        [ ! -f "$FAKE_DOCKER_STATE/orphan" ] || printf 'agenttransfer-app/demo:r3\n'
      fi
    elif [ "$sub" = "rm" ]; then
      target="$1"
      if [ "$target" = "sha256:__IMAGE1__" ]; then
        printf 'conflict: image is referenced by multiple repositories\n' >&2
        exit 1
      fi
      if [ "$target" = 'agenttransfer-app/demo:r1' ]; then rm -f "$FAKE_DOCKER_STATE/image1"; fi
      if [ "$target" = 'agenttransfer-app/demo:r2' ]; then rm -f "$FAKE_DOCKER_STATE/image2"; fi
      if [ "$target" = 'agenttransfer-app/demo:r3' ]; then rm -f "$FAKE_DOCKER_STATE/orphan"; fi
      if [ "$target" = 'unrelated/example:keep' ]; then rm -f "$FAKE_DOCKER_STATE/unrelated"; fi
      printf '%s\n' "$target"
    else
      exit 2
    fi
    ;;
  network)
    sub="$1"; shift
    if [ "$sub" = "rm" ]; then
      printf 'Error response from daemon: network %s not found\n' "$1" >&2
      exit 1
    fi
    exit 2
    ;;
  *) exit 2 ;;
esac
`
	script = strings.NewReplacer(
		"__ID1__", id1, "__ID2__", id2,
		"__IMAGE1__", image1,
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
	if err := os.MkdirAll(root, 0o700); err != nil {
		panic(err)
	}
	return RunnerConfig{
		BuildRoot: root, DataRoot: testDataRoot(root), SnapshotRoot: testSnapshotRoot(root),
		SocketPath: socket, SocketMode: 0o600, AuthToken: testToken,
		AllowSourceBuilds: true,
		RuntimeEgress:     true,
		DockerPath:        fake.path, CommandTimeout: 2 * time.Second,
		BuildTimeout: 2 * time.Second, HealthTimeout: 2 * time.Second,
		MaxOutputBytes: 4096, MaxLogLines: 500,
		CPUCount: 0.75, MemoryBytes: 128 << 20, PIDsLimit: 64,
		TmpfsSizeBytes: 8 << 20, ContainerUID: uid, ContainerGID: gid,
	}
}

func testDataRoot(buildRoot string) string {
	return buildRoot + "-data"
}

func testSnapshotRoot(buildRoot string) string {
	return buildRoot + "-snapshots"
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
	ln, err := net.Listen("tcp", "0.0.0.0:0")
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

func testPrivateIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range addrs {
		ip, _, err := net.ParseCIDR(raw.String())
		if err == nil && ip.To4() != nil && ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Skip("test host has no private IPv4 interface")
	return ""
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
	if _, err := os.Stat(filepath.Join(cfg.SnapshotRoot, "demo", "r1")); !os.IsNotExist(err) {
		t.Fatalf("successful build snapshot survived: %v", err)
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
	route, err := client.RuntimeRoute(context.Background(), testRuntimeID)
	if err != nil || route.AppID != "demo" || route.URL != deployed.Upstream {
		t.Fatalf("runtime route = %+v, %v", route, err)
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
	restarted, err := client.StartRuntime(context.Background(), testRuntimeID)
	if err != nil || !restarted.Running || restarted.URL != deployed.Upstream {
		t.Fatalf("restarted runtime status = %+v, %v", restarted, err)
	}
	if _, err := client.StopRuntime(context.Background(), testRuntimeID); err != nil {
		t.Fatalf("restop runtime: %v", err)
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
		"ARG=<network>\nARG=<create>",
		"ARG=<com.docker.network.bridge.enable_icc=false>",
		"ARG=<--network>\nARG=<agenttransfer-net-demo>",
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
		"CALL\nARG=<update>\nARG=<--restart>\nARG=<unless-stopped>\nARG=<" + testRuntimeID + ">",
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

func TestHealthFailsClosedWhenDockerIsUnavailable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))
	t.Setenv("FAKE_DOCKER_UNHEALTHY", "1")
	err := client.Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health error = %v", err)
	}
}

func TestInternalNetworkCapabilityIsLearnedByFirstDeployment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	ip := testPrivateIPv4(t)
	port := startHealthServer(t)
	fake := newFakeDocker(t, port, "demo", "agenttransfer-app/demo:r1")
	t.Setenv("FAKE_DOCKER_INTERNAL", "true")
	t.Setenv("FAKE_DOCKER_IP", ip)
	t.Setenv("FAKE_DOCKER_SUBNET", ip+"/32")
	t.Setenv("FAKE_DOCKER_CONTAINER_PORT", strconv.Itoa(port))
	t.Setenv("FAKE_DOCKER_CLEAR_IP_WHEN_STOPPED", "1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.RuntimeEgress = false
	client := startRunner(t, cfg)
	readiness, err := client.Readiness(context.Background())
	if err != nil || !readiness.DockerHealthy || readiness.ContainerReady || readiness.ContainerState != "unknown" {
		t.Fatalf("initial readiness = %#v, %v", readiness, err)
	}
	deployed, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1",
		ContainerPort: port, HealthPath: "/ready",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, parseErr := url.Parse(deployed.Upstream)
	if parseErr != nil || u.Scheme != "http" || u.Hostname() != ip || u.Port() == "" {
		t.Fatalf("internal upstream = %q", deployed.Upstream)
	}
	readiness, err = client.Readiness(context.Background())
	if err != nil || !readiness.ContainerReady || readiness.ContainerState != "ready" {
		t.Fatalf("learned readiness = %#v, %v", readiness, err)
	}
	logText, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logText), "ARG=<--publish>") {
		t.Fatalf("internal network deployment published a host port\n%s", logText)
	}
	if _, err := client.StopRuntime(context.Background(), deployed.RuntimeID); err != nil {
		t.Fatalf("stop internal runtime: %v", err)
	}
	t.Setenv("FAKE_DOCKER_EMPTY_IP_ONCE", "1")
	restartedStatus, err := client.StartRuntime(context.Background(), deployed.RuntimeID)
	if err != nil || restartedStatus.URL != deployed.Upstream {
		t.Fatalf("restart internal runtime = %#v, %v", restartedStatus, err)
	}
	// Capability state is process-local, so a replacement runner must recover
	// it from an existing labeled runtime instead of hiding container hosting
	// until another deployment happens.
	restartedCfg := cfg
	restartedCfg.SocketPath = shortSocket(t)
	restarted := startRunner(t, restartedCfg)
	restartedReadiness, err := restarted.Readiness(context.Background())
	if err != nil || !restartedReadiness.ContainerReady || restartedReadiness.ContainerState != "ready" {
		t.Fatalf("restart readiness = %#v, %v", restartedReadiness, err)
	}
}

func TestStartRuntimeStopsRestartWhoseRouteNeverAppears(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	ip := testPrivateIPv4(t)
	port := startHealthServer(t)
	fake := newFakeDocker(t, port, "demo", "agenttransfer-app/demo:r1")
	t.Setenv("FAKE_DOCKER_INTERNAL", "true")
	t.Setenv("FAKE_DOCKER_IP", ip)
	t.Setenv("FAKE_DOCKER_SUBNET", ip+"/32")
	t.Setenv("FAKE_DOCKER_CONTAINER_PORT", strconv.Itoa(port))
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.RuntimeEgress = false
	client := startRunner(t, cfg)
	deployed, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1",
		ContainerPort: port, HealthPath: "/ready",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StopRuntime(context.Background(), deployed.RuntimeID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_EMPTY_IP_ALWAYS", "1")
	restartCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	_, err = client.StartRuntime(restartCtx, deployed.RuntimeID)
	cancel()
	if err == nil {
		t.Fatal("restart without a route unexpectedly succeeded")
	}
	deadline := time.Now().Add(time.Second)
	for {
		state, readErr := os.ReadFile(fake.state)
		if readErr == nil && string(state) == "stopped" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unroutable restart was not stopped: state=%q err=%v", state, readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestInternalRuntimeRejectsUnsafeOrMismatchedAddresses(t *testing.T) {
	tests := []struct {
		name, ip, subnet, want string
	}{
		{"public", "8.8.8.8", "8.8.8.0/24", "not a private IPv4"},
		{"loopback", "127.0.0.2", "127.0.0.0/8", "not a private IPv4"},
		{"link-local", "169.254.10.2", "169.254.0.0/16", "not a private IPv4"},
		{"subnet mismatch", "10.1.0.2", "10.2.0.0/16", "outside its private IPAM subnet"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "apps")
			fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
			t.Setenv("FAKE_DOCKER_INTERNAL", "true")
			t.Setenv("FAKE_DOCKER_IP", tc.ip)
			t.Setenv("FAKE_DOCKER_SUBNET", tc.subnet)
			cfg := testRunnerConfig(root, shortSocket(t), fake)
			cfg.RuntimeEgress = false
			client := startRunner(t, cfg)
			_, err := client.Deploy(context.Background(), DeployRequest{
				AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", HealthPath: "/ready",
			})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway || !strings.Contains(apiErr.Message, tc.want) {
				t.Fatalf("unsafe endpoint error = %v", err)
			}
		})
	}
}

func TestDeploymentReportsContainerExitBeforeNetworkValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	t.Setenv("FAKE_DOCKER_INTERNAL", "true")
	t.Setenv("FAKE_DOCKER_EXIT_IMMEDIATELY", "1")
	t.Setenv("FAKE_DOCKER_EXIT_CODE", "23")
	// Docker may clear all endpoint metadata as soon as a short-lived process
	// exits. The deployment error must still report the process outcome first.
	t.Setenv("FAKE_DOCKER_CLEAR_NETWORK_WHEN_STOPPED", "1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.RuntimeEgress = false
	client := startRunner(t, cfg)

	_, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", HealthPath: "/ready",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("immediate-exit error = %v", err)
	}
	if want := "container exited before health check (exit code 23)"; apiErr.Message != want {
		t.Fatalf("immediate-exit message = %q, want %q", apiErr.Message, want)
	}
	for _, path := range []string{fake.state, fake.state + ".image", fake.state + ".network"} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("failed deployment left %s: %v", path, statErr)
		}
	}
	calls, readErr := os.ReadFile(fake.log)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(calls), "CALL\nARG=<update>") {
		t.Fatal("failed runtime received an automatic restart policy before health succeeded")
	}
}

func TestDeploymentWaitsThroughRunningWithoutIPAndReportsSubsequentExit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	t.Setenv("FAKE_DOCKER_INTERNAL", "true")
	t.Setenv("FAKE_DOCKER_EMPTY_IP_THEN_EXIT", "1")
	t.Setenv("FAKE_DOCKER_EXIT_CODE", "42")
	t.Setenv("FAKE_DOCKER_CLEAR_NETWORK_WHEN_STOPPED", "1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.RuntimeEgress = false
	client := startRunner(t, cfg)

	_, err := client.Deploy(context.Background(), DeployRequest{
		AppID: "demo", ReleaseID: "r1", Image: "agenttransfer-app/demo:r1", HealthPath: "/ready",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("transient empty-IP exit error = %v", err)
	}
	if want := "container exited before health check (exit code 42)"; apiErr.Message != want {
		t.Fatalf("transient empty-IP exit message = %q, want %q", apiErr.Message, want)
	}
	for _, path := range []string{fake.state, fake.state + ".inspected", fake.state + ".image", fake.state + ".network"} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("failed deployment left %s: %v", path, statErr)
		}
	}
}

func TestBuildAdmissionIsBoundedAndContextAware(t *testing.T) {
	r := &runner{buildAdmission: make(chan struct{}, 2), buildSlot: make(chan struct{}, 1)}
	releaseActive, err := r.acquireBuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	queuedResult := make(chan error, 1)
	go func() {
		release, err := r.acquireBuild(queuedCtx)
		if release != nil {
			release()
		}
		queuedResult <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(r.buildAdmission) != cap(r.buildAdmission) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(r.buildAdmission) != cap(r.buildAdmission) {
		t.Fatal("second build never entered the bounded queue")
	}
	if _, err := r.acquireBuild(context.Background()); !errors.Is(err, errBuildQueueFull) {
		t.Fatalf("overflow error = %v", err)
	}
	cancelQueued()
	if err := <-queuedResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation = %v", err)
	}
	releaseActive()
	if got := len(r.buildAdmission); got != 0 {
		t.Fatalf("admission slots leaked: %d", got)
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

	linked := filepath.Join(root, "linked-file")
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(linked, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(linked, "payload")); err != nil {
		t.Fatal(err)
	}
	_, err = client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: linked})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest || !strings.Contains(apiErr.Message, "symlink") {
		t.Fatalf("snapshot symlink error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(testSnapshotRoot(root), "demo", "r1")); !os.IsNotExist(err) {
		t.Fatalf("failed build snapshot survived: %v", err)
	}
}

func TestSourceBuildsRequireExplicitRunnerOptIn(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	contextDir := materializeContext(t, root)
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.AllowSourceBuilds = false
	client := startRunner(t, cfg)
	_, err := client.Build(context.Background(), BuildRequest{AppID: "demo", ReleaseID: "r1", ContextDir: contextDir})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled source build error = %v", err)
	}
	calls, readErr := os.ReadFile(fake.log)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(calls), "ARG=<build>") {
		t.Fatalf("disabled source build reached Docker:\n%s", calls)
	}
}

func TestRunnerRejectsOverlappingAndSymlinkedOwnedRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "builds")
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	cfg.DataRoot = filepath.Join(root, "data")
	if _, err := newRunner(cfg); err == nil || !strings.Contains(err.Error(), "non-nested") {
		t.Fatalf("overlapping roots error = %v", err)
	}

	cfg = testRunnerConfig(root, shortSocket(t), fake)
	target := filepath.Join(t.TempDir(), "snapshot-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(cfg.SnapshotRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, cfg.SnapshotRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := newRunner(cfg); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("symlinked snapshot root error = %v", err)
	}
}

func TestRunnerClearsTransientSnapshotRootOnStartup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "builds")
	fake := newFakeDocker(t, startHealthServer(t), "demo", "agenttransfer-app/demo:r1")
	cfg := testRunnerConfig(root, shortSocket(t), fake)
	stale := filepath.Join(cfg.SnapshotRoot, "stale", "partial")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "Dockerfile"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRunner(cfg); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(cfg.SnapshotRoot); err != nil || len(entries) != 0 {
		t.Fatalf("snapshot root was not cleared: entries=%v err=%v", entries, err)
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
	if err := os.MkdirAll(testDataRoot(root), 0o700); err != nil {
		t.Fatal(err)
	}
	escape := t.TempDir()
	if err := os.Symlink(escape, filepath.Join(testDataRoot(root), "demo")); err != nil {
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
	if _, statErr := os.Stat(fake.state + ".image"); !os.IsNotExist(statErr) {
		t.Fatalf("pre-start data failure left the release image behind: %v", statErr)
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
	r := &runner{cfg: RunnerConfig{ImagePrefix: defaultImagePrefix, AllowedRegistries: []string{"docker.io", "ghcr.io"}}}
	pinned := "ghcr.io/acme/widget@sha256:" + digest
	if err := r.validateDeploy(DeployRequest{AppID: "demo", ReleaseID: "r1", Image: pinned}); err != nil {
		t.Fatalf("pinned allowed image rejected: %v", err)
	}
	for _, image := range []string{
		"ghcr.io/acme/widget:latest",
		"localhost:5000/acme/widget@sha256:" + digest,
		"registry.internal/acme/widget@sha256:" + digest,
	} {
		if err := r.validateDeploy(DeployRequest{AppID: "demo", ReleaseID: "r1", Image: image}); err == nil {
			t.Errorf("external image policy accepted %q", image)
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

func TestDockerfileSourcePolicyRejectsRemoteFetchBypasses(t *testing.T) {
	r := &runner{cfg: RunnerConfig{AllowedRegistries: []string{"docker.io", "ghcr.io"}}}
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, dockerfile string
		wantErr          bool
	}{
		{"scratch", "FROM scratch\n", false},
		{"pinned", "FROM ghcr.io/acme/base@sha256:" + digest + " AS build\nCOPY --from=build /x /x\n", false},
		{"remote frontend", "# syntax=registry.internal/frontend:latest\nFROM scratch\n", true},
		{"compact remote frontend", "#syntax=registry.internal/frontend:latest\nFROM scratch\n", true},
		{"bom remote frontend", "\ufeff# syntax=registry.internal/frontend:latest\nFROM scratch\n", true},
		{"remote add", "FROM scratch\nADD https://internal.example/secret /x\n", true},
		{"local add also fails closed", "FROM scratch\nADD payload /x\n", true},
		{"quoted git add", "FROM scratch\nADD \"git@github.com:moby/buildkit.git#main\" /src\n", true},
		{"escaped git add", "FROM scratch\nADD git\\@github.com:moby/buildkit.git#main /src\n", true},
		{"escaped remote add", "FROM scratch\nADD https:\\/\\/internal.example/secret /x\n", true},
		{"json escaped remote add", "FROM scratch\nADD [\"https\\u003a\\u002f\\u002finternal.example/secret\",\"/x\"]\n", true},
		{"remote add continuation", "FROM scratch\nADD \\\n https://internal.example/secret /x\n", true},
		{"variable remote add", "FROM scratch\nARG U=https://internal.example/secret\nADD $U /x\n", true},
		{"local copy", "FROM scratch\nCOPY payload /x\n", false},
		{"json local copy fails closed", "FROM scratch\nCOPY [\"payload\",\"/x\"]\n", true},
		{"external copy", "FROM scratch\nCOPY --from=registry.internal/base:tag /x /x\n", true},
		{"separated external copy", "FROM scratch\nCOPY --from registry.internal/base:tag /x /x\n", true},
		{"quoted external copy", "FROM scratch\nCOPY --from=\"registry.internal/base:tag\" /x /x\n", true},
		{"escaped external copy", "FROM scratch\nCOPY --fr\\om=registry.internal/base:tag /x /x\n", true},
		{"external copy continuation", "FROM scratch\nCOPY \\\n --from=registry.internal/base:tag /x /x\n", true},
		{"variable copy source", "FROM scratch\nARG P=payload\nCOPY $P /x\n", true},
		{"variable copy from", "FROM scratch\nARG I=registry.internal/base:tag\nCOPY --from=$I /x /x\n", true},
		{"run mount", "FROM scratch\nRUN --mount=type=bind,from=registry.internal/base,target=/x true\n", true},
		{"run cache mount", "FROM scratch\nRUN --mount=type=cache,id=cross-tenant,target=/cache true\n", true},
		{"quoted run mount", "FROM scratch\nRUN \"--mount=type=cache,target=/cache\" true\n", true},
		{"escaped run mount", "FROM scratch\nRUN --mou\\nt=type=cache,target=/cache true\n", true},
		{"run mount continuation", "FROM scratch\nRUN --mount=type=bind,\\\nfrom=registry.internal/base,target=/x true\n", true},
		{"variable run mount", "FROM scratch\nARG I=registry.internal/base:tag\nRUN --mount=type=bind,from=$I,target=/x true\n", true},
		{"variable whole run mount", "FROM scratch\nARG M=type=bind,from=registry.internal/base\nRUN --mount=$M true\n", true},
		{"run network override", "FROM scratch\nRUN --network=host true\n", true},
		{"plain run", "FROM scratch\nRUN echo \"hello\"\n", false},
		{"from option", "FROM --platform=linux/amd64 ghcr.io/acme/base@sha256:" + digest + "\n", true},
		{"quoted from", "FROM \"ghcr.io/acme/base@sha256:" + digest + "\"\n", true},
		{"escaped from", "FROM ghcr.io/acme/ba\\se@sha256:" + digest + "\n", true},
		{"heredoc stage forgery", "FROM scratch\nRUN <<EOF\nFROM scratch AS forged\nEOF\nCOPY --from=forged /x /x\n", true},
		{"custom escape continuation", "# escape=`\nFROM scratch\nADD `\n https://internal.example/secret /x\n", true},
		{"onbuild source", "FROM scratch\nONBUILD ADD https://internal.example/secret /x\n", true},
		{"benign continuation fails closed", "FROM scratch\nRUN echo hello \\\n world\n", true},
		{"tagged base", "FROM alpine:latest\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Dockerfile")
			if err := os.WriteFile(path, []byte(tc.dockerfile), 0o600); err != nil {
				t.Fatal(err)
			}
			err := r.validateDockerfileSources(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("policy error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
	t.Run("oversized policy tail cannot hide forbidden source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "Dockerfile")
		dockerfile := "FROM scratch\n" + strings.Repeat("# filler\n", (1<<20)/9+1) +
			"ADD https://internal.example/secret /x\n"
		if len(dockerfile) <= 1<<20 {
			t.Fatal("test Dockerfile did not exceed policy limit")
		}
		if err := os.WriteFile(path, []byte(dockerfile), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := r.validateDockerfileSources(path); err == nil || !strings.Contains(err.Error(), "1 MiB") {
			t.Fatalf("oversized Dockerfile policy error = %v", err)
		}
	})
}

func TestRemoveImageTargetsOnlyDerivedManagedReference(t *testing.T) {
	root := filepath.Join(t.TempDir(), "apps")
	fake := newFakeDocker(t, 1, "demo", "agenttransfer-app/demo:r1")
	if err := os.WriteFile(fake.state+".image", []byte("built"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := startRunner(t, testRunnerConfig(root, shortSocket(t), fake))

	removed, err := client.RemoveImage(context.Background(), "demo", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !removed.Removed || removed.Image != "agenttransfer-app/demo:r1" {
		t.Fatalf("RemoveImage = %+v", removed)
	}
	again, err := client.RemoveImage(context.Background(), "demo", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Removed {
		t.Fatalf("idempotent RemoveImage = %+v", again)
	}
	if _, err := client.RemoveImage(context.Background(), "demo", "../foreign"); err == nil {
		t.Fatal("RemoveImage accepted an invalid release id")
	}
	logBytes, err := os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "ARG=<image>\nARG=<rm>\nARG=<agenttransfer-app/demo:r1>") ||
		strings.Contains(logText, "ARG=<image>\nARG=<rm>\nARG=<sha256:") {
		t.Fatalf("RemoveImage did not stay confined to the derived tag:\n%s", logText)
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
	image := "ghcr.io/acme/widget@sha256:" + strings.Repeat("a", 64)
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
	runtimeImage := defaultImagePrefix + "-external/demo:r1"
	if !strings.Contains(logText, "ARG=<"+runtimeImage+">\nARG=</app>\nARG=<--literal=$(touch /tmp/nope)>") {
		t.Fatalf("external image command argv ordering is wrong\n%s", logText)
	}
	if !strings.Contains(logText, "ARG=<image>\nARG=<tag>\nARG=<sha256:"+testImageID+">\nARG=<"+runtimeImage+">") ||
		!strings.Contains(logText, "ARG=<image>\nARG=<rm>\nARG=<"+image+">") {
		t.Fatalf("external image was not pinned and its source tag released\n%s", logText)
	}
	if _, err := client.RemoveRuntime(context.Background(), testRuntimeID); err != nil {
		t.Fatal(err)
	}
	calls, err = os.ReadFile(fake.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "ARG=<image>\nARG=<rm>\nARG=<"+runtimeImage+">") {
		t.Fatalf("external runner-owned image reference was not reclaimed\n%s", calls)
	}
	if strings.Contains(string(calls), "ARG=<image>\nARG=<rm>\nARG=<sha256:"+testImageID+">") {
		t.Fatalf("external image was removed by shared immutable id\n%s", calls)
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
	dataDir := filepath.Join(testDataRoot(root), "demo")
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
	if _, err := os.Stat(fake.state + ".network"); !os.IsNotExist(err) {
		t.Fatalf("private app network survived purge: %v", err)
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
	dataDir := filepath.Join(testDataRoot(root), "demo")
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
	for _, name := range []string{"runtime1", "runtime2", "image1", "image2", "orphan"} {
		if _, err := os.Stat(filepath.Join(fake.state, name)); !os.IsNotExist(err) {
			t.Errorf("fake Docker resource %s survived: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(fake.state, "unrelated")); err != nil {
		t.Fatalf("unrelated tag sharing the app image ID was removed: %v", err)
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
		"ARG=<image>\nARG=<rm>\nARG=<agenttransfer-app/demo:r1>",
		"ARG=<image>\nARG=<rm>\nARG=<agenttransfer-app/demo:r2>",
		"ARG=<image>\nARG=<rm>\nARG=<agenttransfer-app/demo:r3>",
		"ARG=<--format>\nARG=<{{.Repository}}:{{.Tag}}>",
		"ARG=<--filter>\nARG=<reference=agenttransfer-app/demo:*>",
		"ARG=<--filter>\nARG=<reference=agenttransfer-app-external/demo:*>",
	} {
		if !strings.Contains(logText, want) {
			t.Errorf("RemoveApp Docker calls missing %q\n%s", want, logText)
		}
	}
	if strings.Contains(logText, "ARG=<image>\nARG=<rm>\nARG=<sha256:"+testImageID+">") ||
		strings.Contains(logText, "ARG=<image>\nARG=<rm>\nARG=<unrelated/example:keep>") {
		t.Fatalf("RemoveApp targeted a shared ID or unrelated reference:\n%s", logText)
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
	if err := os.MkdirAll(filepath.Join(testDataRoot(root), "demo"), 0o700); err != nil {
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
