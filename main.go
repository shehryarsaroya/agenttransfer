// Command agenttransfer gives AI agents a small home on the internet: an
// email address, API key, folder, inbox, and—after human email verification—
// a stable subdomain for a static site or containerized app. Email carries
// handoffs, HTTPS carries content-addressed bytes, and transfer/lifecycle
// events can leave instance-signed audit receipts.
//
// One binary contains the server (`agenttransfer serve`), the client CLI, the
// local MCP bridge, the Docker-facing app runner (`agenttransfer app-runner`),
// the demo, and the self-host preflight (`agenttransfer doctor`).
package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	"github.com/shehryarsaroya/agenttransfer/internal/cli"
	"github.com/shehryarsaroya/agenttransfer/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(cli.Run(nil))
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			log.Fatalf("agenttransfer: %v", err)
		}
	case "app-runner":
		if err := runAppRunner(); err != nil {
			log.Fatalf("agenttransfer app-runner: %v", err)
		}
	case "demo":
		if err := cli.Demo(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "demo failed:", err)
			os.Exit(1)
		}
	case "doctor":
		os.Exit(cli.Doctor(os.Stdout))
	case "version", "--version", "-v":
		fmt.Println("agenttransfer", server.Version)
	case "help", "--help", "-h":
		os.Exit(cli.Run(nil))
	default:
		os.Exit(cli.Run(os.Args[1:]))
	}
}

// runAppRunner starts the separate, narrow Docker control process used only
// for dynamic apps. The public API service talks to it over an authenticated
// Unix socket and never receives direct Docker access.
func runAppRunner() error {
	if strings.TrimSpace(os.Getenv("APP_ROOT")) != "" {
		return fmt.Errorf("APP_ROOT is unsafe and no longer supported; set distinct APP_BUILD_ROOT and APP_DATA_ROOT")
	}
	cfg := apphost.RunnerConfig{
		SocketPath:   strings.TrimSpace(os.Getenv("APP_RUNNER_SOCKET")),
		AuthToken:    strings.TrimSpace(os.Getenv("APP_RUNNER_TOKEN")),
		BuildRoot:    strings.TrimSpace(os.Getenv("APP_BUILD_ROOT")),
		DataRoot:     strings.TrimSpace(os.Getenv("APP_DATA_ROOT")),
		SnapshotRoot: strings.TrimSpace(os.Getenv("APP_SNAPSHOT_ROOT")),
		DockerPath:   strings.TrimSpace(os.Getenv("APP_DOCKER_PATH")),
		ImagePrefix:  strings.TrimSpace(os.Getenv("APP_IMAGE_PREFIX")),
		BuildNetwork: strings.ToLower(strings.TrimSpace(os.Getenv("APP_BUILD_NETWORK"))),
		AllowedRegistries: strings.FieldsFunc(envDefault("APP_ALLOWED_REGISTRIES", "docker.io,ghcr.io"), func(r rune) bool {
			return r == ','
		}),
	}
	if cfg.BuildRoot == "" {
		return fmt.Errorf("APP_BUILD_ROOT is required")
	}
	if cfg.DataRoot == "" {
		return fmt.Errorf("APP_DATA_ROOT is required and must be separate from APP_BUILD_ROOT")
	}
	if cfg.SnapshotRoot == "" {
		return fmt.Errorf("APP_SNAPSHOT_ROOT is required and must be separate from durable APP_DATA_ROOT")
	}
	if cfg.SocketPath == "" {
		return fmt.Errorf("APP_RUNNER_SOCKET is required")
	}
	if cfg.AuthToken == "" {
		return fmt.Errorf("APP_RUNNER_TOKEN is required (use a shared random value of at least 32 bytes)")
	}
	if raw := strings.TrimSpace(os.Getenv("APP_RUNNER_SOCKET_MODE")); raw != "" {
		mode, err := strconv.ParseUint(strings.TrimPrefix(raw, "0o"), 8, 32)
		if err != nil {
			return fmt.Errorf("APP_RUNNER_SOCKET_MODE: %w", err)
		}
		cfg.SocketMode = os.FileMode(mode)
	}
	var err error
	if cfg.CPUCount, err = floatEnv("APP_CPU", 2); err != nil {
		return err
	}
	if cfg.MemoryBytes, err = sizeEnv("APP_MEMORY", "2GB"); err != nil {
		return err
	}
	if cfg.TmpfsSizeBytes, err = sizeEnv("APP_TMPFS_SIZE", "256MB"); err != nil {
		return err
	}
	if cfg.MaxBuildContextBytes, err = sizeEnv("APP_MAX_BUILD_CONTEXT", "10GB"); err != nil {
		return err
	}
	if cfg.MaxImageBytes, err = sizeEnv("APP_MAX_IMAGE_SIZE", "10GB"); err != nil {
		return err
	}
	if cfg.PIDsLimit, err = intEnv("APP_PIDS_LIMIT", 256); err != nil {
		return err
	}
	if cfg.ContainerUID, err = boundedIntEnv("APP_CONTAINER_UID", 65532, math.MaxInt32); err != nil {
		return err
	}
	if cfg.ContainerGID, err = boundedIntEnv("APP_CONTAINER_GID", 65532, math.MaxInt32); err != nil {
		return err
	}
	if cfg.MaxBuildQueue, err = boundedIntEnv("APP_BUILD_QUEUE", 8, math.MaxInt); err != nil {
		return err
	}
	if cfg.RuntimeEgress, err = boolEnv("APP_RUNTIME_EGRESS", false); err != nil {
		return err
	}
	if cfg.AllowSourceBuilds, err = boolEnv("APP_ALLOW_SOURCE_BUILDS", false); err != nil {
		return err
	}
	if maxLogLines, err := intEnv("APP_MAX_LOG_LINES", 2000); err != nil {
		return err
	} else if maxLogLines < 2000 {
		return fmt.Errorf("APP_MAX_LOG_LINES must be at least 2000 (the public API cap)")
	} else if maxLogLines > 10000 {
		return fmt.Errorf("APP_MAX_LOG_LINES may not exceed 10000")
	} else {
		cfg.MaxLogLines = int(maxLogLines)
	}
	if cfg.BuildTimeout, err = durationEnv("APP_BUILD_TIMEOUT", "15m"); err != nil {
		return err
	}
	if cfg.PullTimeout, err = durationEnv("APP_PULL_TIMEOUT", "10m"); err != nil {
		return err
	}
	if cfg.HealthTimeout, err = durationEnv("APP_HEALTH_TIMEOUT", "60s"); err != nil {
		return err
	}
	if cfg.ContainerPort, err = boundedIntEnv("APP_CONTAINER_PORT", 8080, 65535); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return apphost.RunRunner(ctx, cfg)
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func sizeEnv(key, fallback string) (int64, error) {
	value := envDefault(key, fallback)
	n, err := server.ParseSize(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func durationEnv(key, fallback string) (time.Duration, error) {
	value := envDefault(key, fallback)
	d, err := server.ParseTTL(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func floatEnv(key string, fallback float64) (float64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive number", key)
	}
	return n, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return b, nil
}

func intEnv(key string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return n, nil
}

func boundedIntEnv(key string, fallback, max int64) (int, error) {
	n, err := intEnv(key, fallback)
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, fmt.Errorf("%s must be at most %d", key, max)
	}
	return int(n), nil
}

func serve(args []string) error {
	cfg, err := server.FromEnv()
	if err != nil {
		return err
	}
	// `serve --connect [url]` — flag sugar over the CONNECT env var.
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--connect":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return fmt.Errorf("--connect needs a connect-host URL (the public agenttransfer.dev instance is retired — run your own connect host, see docs/connect.md)")
			}
			cfg.Connect = strings.TrimRight(args[i+1], "/")
			i++
		case strings.HasPrefix(args[i], "--connect="):
			cfg.Connect = strings.TrimRight(strings.TrimPrefix(args[i], "--connect="), "/")
		default:
			return fmt.Errorf("unknown serve flag %q (only --connect [url])", args[i])
		}
	}

	srv, firstBootAdmin, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	if firstBootAdmin != "" {
		fmt.Fprintf(os.Stderr, `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 First boot — your ADMIN TOKEN (shown once, stored only as a hash):

   %s

 Create your first agent:

   curl -X POST %s/v1/agents \
     -H "Authorization: Bearer %s" \
     -d '{"name":"my-agent"}'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`, firstBootAdmin, srv.BaseURL(), firstBootAdmin)
	}
	if cfg.Connect != "" {
		fmt.Fprintf(os.Stderr, "connect: borrowing a public URL + email from %s\n"+
			"connect: watch the log for your https://<name>.… address; agents can RECEIVE email immediately.\n"+
			"connect: to unlock SENDING email, verify an owner:\n"+
			"  curl -X POST %s/v1/connect/verify -H \"Authorization: Bearer <admin token>\" -d '{\"email\":\"you@example.com\"}'\n",
			cfg.Connect, "http://localhost"+cfg.HTTPAddr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}
