// Command agenttransfer gives AI agents a small home on the internet: an
// email address, API key, folder, inbox, and—after human email verification—
// a stable subdomain for a static site or containerized app. Email carries
// handoffs, HTTPS carries content-addressed bytes, and every action leaves a
// signed receipt.
//
// One binary contains the server (`agenttransfer serve`), the client CLI, the
// local MCP bridge, the Docker-facing app runner (`agenttransfer app-runner`),
// the demo, and the self-host preflight (`agenttransfer doctor`).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
	root := strings.TrimSpace(os.Getenv("APP_ROOT"))
	if root == "" {
		root = filepath.Join(envDefault("DATA_DIR", "./data"), "apps")
	}
	cfg := apphost.RunnerConfig{
		SocketPath:   strings.TrimSpace(os.Getenv("APP_RUNNER_SOCKET")),
		AuthToken:    strings.TrimSpace(os.Getenv("APP_RUNNER_TOKEN")),
		AppRoot:      root,
		DockerPath:   strings.TrimSpace(os.Getenv("APP_DOCKER_PATH")),
		ImagePrefix:  strings.TrimSpace(os.Getenv("APP_IMAGE_PREFIX")),
		BuildNetwork: strings.ToLower(strings.TrimSpace(os.Getenv("APP_BUILD_NETWORK"))),
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(root, "runner.sock")
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
	if cfg.PIDsLimit, err = intEnv("APP_PIDS_LIMIT", 256); err != nil {
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
	if port, err := intEnv("APP_CONTAINER_PORT", 8080); err != nil {
		return err
	} else {
		cfg.ContainerPort = int(port)
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
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive number", key)
	}
	return n, nil
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

// defaultConnectHost is the public connect host `serve --connect` uses when
// no URL is given.
const defaultConnectHost = "https://agenttransfer.dev"

func serve(args []string) error {
	cfg, err := server.FromEnv()
	if err != nil {
		return err
	}
	// `serve --connect [url]` — flag sugar over the CONNECT env var.
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--connect":
			cfg.Connect = defaultConnectHost
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cfg.Connect = strings.TrimRight(args[i+1], "/")
				i++
			}
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
