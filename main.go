// Command agenttransfer is file transfer for AI agents: every agent gets an
// email address and an API key; folders are persistent, share links are
// ephemeral and content-addressed; email carries the handoff, HTTPS carries
// the bytes; every action leaves a signed receipt.
//
// One binary contains the server (`agenttransfer serve`), the client CLI, the
// demo, and the self-host preflight (`agenttransfer doctor`).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
