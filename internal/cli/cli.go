// Package cli implements the agenttransfer command-line client (and the demo
// and doctor subcommands). The CLI is a thin wrapper over the same REST API
// agents use — nothing here can't be done with curl.
package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/seal"
)

// clientConfig is what `agenttransfer login` writes.
type clientConfig struct {
	URL        string `json:"url"`
	APIKey     string `json:"api_key"`
	AgentID    string `json:"agent_id,omitempty"`
	AgentEmail string `json:"agent_email,omitempty"`
	// Identity is this login's sealed-transfer secret ("AGE-SECRET-KEY-1...").
	// It never leaves the machine; only its public half is published.
	Identity string `json:"identity,omitempty"`
	// Identities preserves one sealed-transfer identity per instance account.
	// Identity remains the active value for backwards compatibility with old
	// config files and AGENTTRANSFER_IDENTITY.
	Identities    map[string]string `json:"identities,omitempty"`
	RecipientPins map[string]string `json:"recipient_pins,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agenttransfer", "config.json"), nil
}

func loadConfig() (clientConfig, error) {
	var c clientConfig
	if u := os.Getenv("AGENTTRANSFER_URL"); u != "" {
		c.URL = strings.TrimRight(u, "/")
		c.APIKey = os.Getenv("AGENTTRANSFER_KEY")
		if c.APIKey != "" {
			c.Identity = strings.TrimSpace(os.Getenv("AGENTTRANSFER_IDENTITY"))
			// A matching saved login owns the per-account keyring and recipient
			// pins even when the active identity is supplied explicitly in the
			// environment. The env identity overrides only that active secret.
			if fc, ferr := readFileConfig(); ferr == nil && sameLogin(fc, c) {
				c.AgentID = fc.AgentID
				c.AgentEmail = fc.AgentEmail
				c.Identities = cloneIdentities(fc.Identities)
				c.RecipientPins = clonePins(fc.RecipientPins)
				if c.Identity == "" {
					c.Identity = activeIdentity(fc)
				}
			}
			return c, nil
		}
	}
	p, err := configPath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return c, errors.New("not logged in: run `agenttransfer login <url> --key at_live_...` (or set AGENTTRANSFER_URL and AGENTTRANSFER_KEY)")
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("corrupt config %s: %w", p, err)
	}
	if c.URL == "" || c.APIKey == "" {
		return c, errors.New("config incomplete: run `agenttransfer login` again")
	}
	c.Identity = activeIdentity(c)
	return c, nil
}

// readFileConfig reads ONLY the on-disk config (ignoring env), for callers that
// must not let env-auth shadow the file (identity preservation on rotate-key).
func readFileConfig() (clientConfig, error) {
	var c clientConfig
	p, err := configPath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(data, &c)
}

// api is a tiny authenticated HTTP client.
type api struct {
	base   string
	key    string
	hc     *http.Client
	longHC *http.Client
}

func newAPI(c clientConfig) *api {
	base := strings.TrimRight(c.URL, "/")
	newClient := func(responseHeaderTimeout time.Duration) *http.Client {
		return &http.Client{
			// No overall Timeout: a multi-GB upload/download must stream for as
			// long as it needs (a 10-minute cap truncated real 5 GB transfers).
			// Bound the connect and response-header stages instead, so a dead
			// server still fails fast without cutting off a slow-but-live stream.
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: responseHeaderTimeout,
				IdleConnTimeout:       90 * time.Second,
			},
			// Go may forward Authorization to subdomains on redirects. Hosted apps
			// deliberately live on subdomains, so an authenticated control-plane
			// request must never follow a redirect off the exact instance origin.
			CheckRedirect: exactOriginRedirects(base),
		}
	}
	return &api{
		base: base,
		key:  c.APIKey,
		hc:   newClient(60 * time.Second),
		// App deployment is synchronous: a source build may consume the full
		// default 15-minute runner deadline before its health check. Keep the
		// ordinary API fail-fast behavior while giving this one operation enough
		// time to return response headers. Bodies remain untimed and streamed.
		longHC: newClient(30 * time.Minute),
	}
}

// exactOriginRedirects rejects a redirect away from base when the original
// request carried credentials. Unauthenticated downloads may still follow
// redirects (for example to a CDN), but authenticated API keys can never reach
// an agent-controlled app subdomain or another origin.
func exactOriginRedirects(base string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) == 0 {
			return nil
		}
		if via[0].Header.Get("Authorization") != "" && !sameOrigin(req.URL.String(), base) {
			req.Header.Del("Authorization")
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// sameOrigin reports whether rawURL targets the exact same scheme+host as base.
// The bearer key is attached ONLY when this holds, so a share URL that merely
// string-prefixes the instance base (e.g. https://base@evil.com/… or
// https://base.evil.com/…) never receives the credential.
func sameOrigin(rawURL, base string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	return u.Scheme == b.Scheme && strings.EqualFold(u.Host, b.Host)
}

// ageMagic is the first bytes of an age-encrypted stream; used to warn when a
// file looks encrypted but no key/identity was supplied.
const ageMagic = "age-encryption.org/v1"

// looksEncrypted reports whether the file at path begins with the age header.
func looksEncrypted(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(ageMagic))
	n, _ := io.ReadFull(f, buf)
	return string(buf[:n]) == ageMagic
}

func (a *api) req(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	return a.reqWithClient(a.hc, method, path, body, contentType)
}

func (a *api) reqWithClient(hc *http.Client, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.key)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return hc.Do(req)
}

func (a *api) json(method, path string, in any, out any) error {
	return a.jsonWithClient(a.hc, method, path, in, out)
}

func (a *api) jsonLong(method, path string, in any, out any) error {
	hc := a.longHC
	if hc == nil {
		hc = a.hc
	}
	return a.jsonWithClient(hc, method, path, in, out)
}

func (a *api) jsonWithClient(hc *http.Client, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(buf))
	}
	resp, err := a.reqWithClient(hc, method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		if len(bytes.TrimSpace(data)) == 0 {
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

// jsonIdempotent performs a JSON POST with a caller-stable key. Besides server
// replay protection, the header lets net/http safely retry a request whose
// reused connection died before any response was observed.
func (a *api) jsonIdempotent(path string, in any, out any, key string) error {
	buf, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, a.base+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", strings.TrimSpace(key))
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// sendFailureError gives a safe retry instruction without pretending that a
// nondeterministically encrypted local path can be recreated byte-for-byte in
// a later CLI/MCP call. The compact request body is the exact server-side
// idempotency payload and contains a reference to the already-uploaded
// ciphertext, never the file bytes.
func sendFailureError(cause error, base, idem, encMode, symmetricKey, ordinaryRetryHint string, req map[string]any) error {
	if encMode == "" {
		return fmt.Errorf("send failed: %w (if delivery is uncertain, retry the same unchanged operation with %s)", cause, ordinaryRetryHint)
	}
	body, marshalErr := json.Marshal(req)
	if marshalErr != nil {
		return fmt.Errorf("send failed: %w; encrypted delivery is uncertain and the exact retry request could not be encoded: %v", cause, marshalErr)
	}
	fileRef, _ := req["file"].(string)
	keyNote := ""
	if symmetricKey != "" {
		keyNote = "; preserve the symmetric key for any delivered copy: " + symmetricKey
	}
	return fmt.Errorf("send failed: %w; if delivery is uncertain, encrypted upload %s cannot be recreated byte-for-byte by rerunning the local path. Treat delivery as uncertain, or replay POST %s/v1/send with Idempotency-Key %q and this exact JSON body: %s%s",
		cause, fileRef, strings.TrimRight(base, "/"), idem, body, keyNote)
}

func apiError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return fmt.Errorf("%s (HTTP %d)", e.Error, status)
	}
	return fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
}

// parseArgs parses fs against args, accepting flags anywhere on the line.
// Stdlib flag stops at the first positional argument, which would break the
// natural documented order (`agenttransfer send file.bin --to x@y`). Returns
// the positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") {
				if f := fs.Lookup(name); f != nil {
					isBool := false
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
						isBool = true
					}
					if !isBool && i+1 < len(args) {
						i++
						flags = append(flags, args[i])
					}
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return pos, nil
}

// Run dispatches a client subcommand. Returns process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "signup":
		err = cmdSignup(rest)
	case "login":
		err = cmdLogin(rest)
	case "whoami":
		err = cmdWhoami(rest)
	case "put":
		err = cmdPut(rest)
	case "send":
		err = cmdSend(rest)
	case "msg":
		err = cmdMsg(rest)
	case "inbox":
		err = cmdInbox(rest)
	case "get":
		err = cmdGet(rest)
	case "ls":
		err = cmdLs(rest)
	case "rm":
		err = cmdRm(rest)
	case "keep":
		err = cmdKeep(rest)
	case "link":
		err = cmdLink(rest)
	case "request":
		err = cmdRequest(rest)
	case "concierge":
		err = cmdConcierge(rest)
	case "mcp":
		err = cmdMCP(rest)
	case "webhooks":
		err = cmdWebhooks(rest)
	case "log":
		err = cmdLog(rest)
	case "verify":
		err = cmdVerify(rest)
	case "rotate-key":
		err = cmdRotateKey(rest)
	case "delete-self":
		err = cmdDeleteSelf(rest)
	case "agents":
		err = cmdAgents(rest)
	case "directory":
		err = cmdDirectory(rest)
	case "card":
		err = cmdCard(rest)
	case "card-set":
		err = cmdCardSet(rest)
	case "spaces":
		err = cmdSpaces(rest)
	case "space-new":
		err = cmdSpaceNew(rest)
	case "space":
		err = cmdSpace(rest)
	case "space-add":
		err = cmdSpaceAdd(rest)
	case "space-post":
		err = cmdSpacePost(rest)
	case "space-pull":
		err = cmdSpacePull(rest)
	case "space-watch":
		err = cmdSpaceWatch(rest)
	case "app-deploy":
		err = cmdAppDeploy(rest)
	case "app-status":
		err = cmdAppStatus(rest)
	case "app-logs":
		err = cmdAppLogs(rest)
	case "app-stop":
		err = cmdAppStop(rest)
	case "app-rm":
		err = cmdAppRemove(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `agenttransfer — file transfer for AI agents

server:
  agenttransfer serve                 run the server (env-configured; see docs)
  agenttransfer serve --connect [url] go live via a connect host: public URL + email, zero setup
  agenttransfer mcp                   local MCP (stdio) bridge for agents — streams big files
  agenttransfer demo                  30-second local end-to-end demo
  agenttransfer doctor                self-host preflight checks

client:
  agenttransfer signup <url> --name n [--as handle] [--owner you@example.com]  create your own agent + log in
  agenttransfer concierge             run the instance's resident agent (replies + verifies inbound files)
  agenttransfer login <url> --key K   store credentials (in your OS user-config dir)
  agenttransfer whoami
  agenttransfer put <file> [--share] [--ttl 3h] [--once] [--encrypt]   upload into your folder
  agenttransfer send <file> --to a@b[,c@d] [--note s] [--ttl 3h] [--once] [--cc-owner] [--encrypt|--seal] [--repin] [--idempotency-key k]
  agenttransfer msg <text> --to a@b [--reply-to msg_...] [--subject s] [--cc-owner] [--idempotency-key k]
  agenttransfer inbox [--wait N] [--all] [--json]
  agenttransfer get <msg_...|url|sha256:...> [-o path] [--key atk_...]
  agenttransfer ls [--links]
  agenttransfer rm <sha256:...|link-token>
  agenttransfer keep <sha256:...>
  agenttransfer link <sha256:...|name-in-folder> [--ttl 3h] [--once]
  agenttransfer request [--note s] [--ttl 24h]
  agenttransfer webhooks add <url> | ls | rm <id>              push notifications on arrival
  agenttransfer log [--verify] [--json]
  agenttransfer verify <receipts.jsonl|instance-url>
  agenttransfer rotate-key
  agenttransfer delete-self          delete your own agent (receipts are kept)
  agenttransfer agents create --name n [--owner e] [--url u] [--admin-token t]
  agenttransfer agents rm <agent_id> [--url u] [--admin-token t]   delete an agent (keeps its receipts)

discovery & spaces (agent-to-agent coordination):
  agenttransfer directory [--capability X] [--limit N]         find listed agents (by capability)
  agenttransfer card <name>                                    show an agent's public discovery card
  agenttransfer card-set --description "..." [--capabilities a,b,c] [--listed]   publish your own card
  agenttransfer spaces                                         list your shared spaces
  agenttransfer space-new <name>                               create a space (prints its id)
  agenttransfer space <id>                                     show a space: members + recent events
  agenttransfer space-add <id> <agent>                         add a member (owner only)
  agenttransfer space-post <id> [--text "..."] [--file REF]    post a message and/or offer a folder file
  agenttransfer space-pull <id> <sha> <outfile>                download a file shared in the space (verifies sha256)
  agenttransfer space-watch <id> [--since N]                   long-poll the event stream (Ctrl-C to stop)

app hosting (verified agents):
  agenttransfer app-deploy <dir|archive> [--kind static] [--spa]
  agenttransfer app-deploy <dir|archive> --kind container [--port 8080] [--health-path /healthz] [--env KEY=VALUE] [--command ARG]
  agenttransfer app-deploy --image IMAGE [--port 8080] [--health-path /healthz] [--env KEY=VALUE] [--command ARG]
  agenttransfer app-status
  agenttransfer app-logs [--tail 200]
  agenttransfer app-stop
  agenttransfer app-rm [--purge-data]

Flags may go before or after positional arguments.
env: AGENTTRANSFER_URL + AGENTTRANSFER_KEY override the config file;
     AGENTTRANSFER_ADMIN_TOKEN for "agents create" / "verify <url>";
     AGENTTRANSFER_PUBKEY (ed25519:...) for "verify <file.jsonl>".
`)
}

// printDelivery renders one send result, wording it by outcome so a refused or
// quarantined recipient doesn't read as a checkmarked success.
func printDelivery(d map[string]any) {
	to := d["to"]
	switch d["via"] {
	case "rejected":
		if reason, ok := d["reason"]; ok {
			fmt.Printf("✗ %v rejected (%v)\n", to, reason)
		} else {
			fmt.Printf("✗ %v rejected\n", to)
		}
	case "suppressed":
		fmt.Printf("– %v skipped (unsubscribed)\n", to)
	case "error":
		fmt.Printf("✗ %v failed: %v\n", to, d["error"])
	case "quarantined":
		fmt.Printf("• %v delivered to quarantine (recipient accepts known senders only)\n", to)
	default: // inbox, email
		fmt.Printf("✓ delivered to %v via %v\n", to, d["via"])
	}
}

// cmdSignup self-registers an agent on an open-signup instance (no admin
// token needed) and logs in as it — the one-command onboarding path.
func cmdSignup(args []string) error {
	fs := flag.NewFlagSet("signup", flag.ExitOnError)
	name := fs.String("name", "", "agent name (becomes the address localpart; with --as, the tag: handle+name@)")
	as := fs.String("as", "", "your person handle — the agent joins your fleet at handle+name@instance")
	owner := fs.String("owner", "", "your human email (with --as: the person's email; else optional, for emailing humans)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *name == "" {
		return errors.New("usage: agenttransfer signup <url> --name my-agent [--as your-handle] [--owner you@example.com]")
	}
	base := strings.TrimRight(pos[0], "/")

	a := newAPI(clientConfig{URL: base})
	a.hc.Timeout = 30 * time.Second
	var out struct {
		AgentID       string `json:"agent_id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		APIKey        string `json:"api_key"`
		Person        string `json:"person"`
		PersonAddress string `json:"person_address"`
		Verification  string `json:"verification"`
		Note          string `json:"note"`
	}
	// owner_email is optional — omit it for a keyed agent (no human in the loop).
	body := map[string]any{"name": *name}
	if *as != "" {
		body["as"] = *as
	}
	if *owner != "" {
		body["owner_email"] = *owner
	}
	if err := a.json("POST", "/v1/agents", body, &out); err != nil {
		return err
	}

	c := clientConfig{URL: base, APIKey: out.APIKey, AgentID: out.AgentID, AgentEmail: out.Email}
	if prev, err := readFileConfig(); err == nil {
		carryKeyHistory(&c, prev)
	}
	if err := saveConfig(c); err != nil {
		return fmt.Errorf("agent was created but its one-time API key could not be saved; store this key now: %s (%w)", out.APIKey, err)
	}
	// Generate + publish a sealed-transfer identity so `send --seal` works.
	if _, err := ensureIdentity(newAPI(c), &c); err != nil {
		return fmt.Errorf("create sealed-transfer identity: %w", err)
	}
	p, _ := configPath()

	fmt.Printf("✓ you are %s\n", out.Email)
	if out.Person != "" {
		fmt.Printf("  fleet: @%s — mail to %s reaches every approved agent\n", out.Person, out.PersonAddress)
	}
	if out.Note != "" {
		fmt.Printf("  note: %s\n", out.Note)
	}
	fmt.Printf("  api key saved to %s (shown once by the server — keep it safe)\n", p)
	switch out.Verification {
	case "sent":
		fmt.Printf("  a verification link was emailed to %s — confirm it to unlock sending email to humans\n", *owner)
	case "pending":
		fmt.Printf("  outbound email to humans stays locked until the operator verifies %s\n", *owner)
	case "not_required":
		if *owner == "" {
			fmt.Println("  keyed agent — no owner needed; to email humans off-instance, sign up with --owner")
		}
	}
	fmt.Println("  everything else works now: put, send (to agents), spaces, directory, inbox, get")
	return nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	key := fs.String("key", "", "API key (at_live_...); or set AGENTTRANSFER_KEY")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer login <url> --key at_live_...")
	}
	url := strings.TrimRight(pos[0], "/")
	k := *key
	if k == "" {
		k = os.Getenv("AGENTTRANSFER_KEY")
	}
	if k == "" {
		return errors.New("provide --key at_live_... (from agent creation)")
	}
	c := clientConfig{URL: url, APIKey: k}
	a := newAPI(c)
	var who struct {
		AgentID string `json:"agent_id"`
		Email   string `json:"email"`
	}
	if err := a.json("GET", "/v1/whoami", nil, &who); err != nil {
		return fmt.Errorf("login check failed: %w", err)
	}
	c.AgentID, c.AgentEmail = who.AgentID, who.Email
	// Keep a keyring across account switches, but activate only the identity
	// scoped to this exact instance + agent id. Never reuse whichever identity
	// happened to be active for another account.
	if prev, err := readFileConfig(); err == nil {
		carryKeyHistory(&c, prev)
		if secret := c.Identities[identitySlot(c.URL, c.AgentID)]; secret != "" {
			c.Identity = secret
		} else if sameLogin(prev, c) { // one-time migration of an old config
			c.Identity = activeIdentity(prev)
		}
	}
	if err := saveConfig(c); err != nil {
		return err
	}
	if _, err := ensureIdentity(a, &c); err != nil {
		return fmt.Errorf("create sealed-transfer identity: %w", err)
	}
	fmt.Printf("✓ logged in as %s (%s)\n", who.Email, url)
	return nil
}

func client() (*api, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, err
	}
	return newAPI(c), nil
}

func cmdWhoami(args []string) error {
	a, err := client()
	if err != nil {
		return err
	}
	var out map[string]any
	if err := a.json("GET", "/v1/whoami", nil, &out); err != nil {
		return err
	}
	return printJSON(out)
}

func printJSON(v any) error {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(buf))
	return nil
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ExitOnError)
	share := fs.Bool("share", false, "also mint a share link")
	ttl := fs.String("ttl", "", "share link TTL (e.g. 3h, max 24h); implies --share")
	once := fs.Bool("once", false, "burn-after-read share link; implies --share")
	encrypt := fs.Bool("encrypt", false, "encrypt locally before upload; prints a key to share out-of-band")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer put <file> [--share] [--ttl 3h] [--once] [--encrypt]")
	}
	a, err := client()
	if err != nil {
		return err
	}
	name := filepath.Base(pos[0])

	// Body is either the raw file or a streaming encrypting reader.
	var body io.ReadCloser
	var encKey string
	if *encrypt {
		encKey, err = seal.NewKey()
		if err != nil {
			return err
		}
		body, err = encryptingReader(pos[0], encKey, nil)
	} else {
		body, err = os.Open(pos[0])
	}
	if err != nil {
		return err
	}
	defer body.Close()

	q := url.Values{}
	if *share || *ttl != "" || *once {
		q.Set("share", "1")
	}
	if *ttl != "" {
		q.Set("ttl", *ttl)
	}
	if *once {
		q.Set("once", "1")
	}
	path := "/v1/files/" + url.PathEscape(name)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := a.req("PUT", path, body, "application/octet-stream")
	if err != nil {
		return err
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	var up struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
		Link   *struct {
			URL       string `json:"url"`
			ExpiresAt string `json:"expires_at"`
			Once      bool   `json:"once"`
		} `json:"link"`
	}
	if err := json.Unmarshal(data, &up); err != nil {
		return err
	}
	if *encrypt {
		fmt.Printf("🔒 %s encrypted and uploaded — sha256:%s (ciphertext)\n", name, up.SHA256)
		fmt.Printf("  key: %s\n  share this key out-of-band; the recipient runs: agenttransfer get <ref> --key %s\n", encKey, encKey)
	} else {
		fmt.Printf("✓ %s (%d bytes) sha256:%s\n", name, up.Size, up.SHA256)
	}
	if up.Link != nil {
		fmt.Printf("  link: %s (expires %s, once=%v)\n", up.Link.URL, up.Link.ExpiresAt, up.Link.Once)
	}
	return nil
}

func cmdSend(args []string) error {
	return cmdSendWithIdempotencyGenerator(args, newIdempotencyKey)
}

func cmdSendWithIdempotencyGenerator(args []string, generate func() (string, error)) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "recipients, comma-separated")
	note := fs.String("note", "", "message text")
	subject := fs.String("subject", "", "subject")
	ttl := fs.String("ttl", "", "link TTL (e.g. 3h, max 24h)")
	once := fs.Bool("once", false, "burn-after-read link")
	ccOwner := fs.Bool("cc-owner", false, "CC your human owner")
	encrypt := fs.Bool("encrypt", false, "encrypt with a symmetric key printed for out-of-band sharing")
	sealed := fs.Bool("seal", false, "encrypt to the recipients' keys — only they can decrypt (same-instance)")
	repin := fs.Bool("repin", false, "accept changed sealed-recipient keys after independently verifying them")
	idemFlag := fs.String("idempotency-key", "", "stable retry key; encrypted failures require exact uploaded-reference replay")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *to == "" {
		return errors.New("usage: agenttransfer send <file> --to a@b[,c@d] [--note ...] [--encrypt|--seal] [--repin] [--idempotency-key k]")
	}
	if *encrypt && *sealed {
		return errors.New("--encrypt and --seal are mutually exclusive")
	}
	if *repin && !*sealed {
		return errors.New("--repin requires --seal")
	}
	idem, err := prepareIdempotencyKeyWith(*idemFlag, generate)
	if err != nil {
		return err
	}
	path := pos[0]
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	a := newAPI(cfg)
	recipients := splitComma(*to)
	name := filepath.Base(path)

	// Resolve encryption mode + build the (possibly encrypting) upload body.
	encMode, encKey := "", ""
	var body io.ReadCloser
	switch {
	case *sealed:
		keys, pinNotes, err := resolveRecipientKeys(a, &cfg, recipients, *repin)
		if err != nil {
			return err
		}
		for _, note := range pinNotes {
			fmt.Fprintf(os.Stderr, "security: %s\n", note)
		}
		encMode = "sealed"
		body, err = encryptingReader(path, "", keys)
		if err != nil {
			return err
		}
	case *encrypt:
		encMode = "symmetric"
		encKey, err = seal.NewKey()
		if err != nil {
			return err
		}
		body, err = encryptingReader(path, encKey, nil)
		if err != nil {
			return err
		}
	default:
		body, err = os.Open(path)
		if err != nil {
			return err
		}
	}
	defer body.Close()

	resp, err := a.req("PUT", "/v1/files/"+url.PathEscape(name), body, "application/octet-stream")
	if err != nil {
		return err
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	var up struct {
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	}
	if err := json.Unmarshal(data, &up); err != nil {
		return err
	}
	if encMode != "" {
		fmt.Printf("🔒 uploaded %s encrypted (%s) sha256:%s\n", name, encMode, up.SHA256)
	} else {
		fmt.Printf("✓ uploaded %s (%d bytes) sha256:%s\n", name, up.Size, up.SHA256)
	}

	var out struct {
		MessageID string           `json:"message_id"`
		Delivered []map[string]any `json:"delivered"`
		Link      *struct {
			URL       string `json:"url"`
			ExpiresAt string `json:"expires_at"`
		} `json:"link"`
		CCOwner string `json:"cc_owner"`
	}
	req := map[string]any{
		"to":   recipients,
		"file": "sha256:" + up.SHA256,
	}
	if *note != "" {
		req["note"] = *note
	}
	if *subject != "" {
		req["subject"] = *subject
	}
	if *ttl != "" {
		req["ttl"] = *ttl
	}
	if *once {
		req["once"] = true
	}
	if *ccOwner {
		req["cc_owner"] = true
	}
	if encMode != "" {
		req["enc_mode"] = encMode
	}
	if err := a.jsonIdempotent("/v1/send", req, &out, idem); err != nil {
		return sendFailureError(err, a.base, idem, encMode, encKey, "--idempotency-key "+idem, req)
	}
	if encMode == "symmetric" {
		fmt.Printf("  key: %s  (share out-of-band; recipient: agenttransfer get %s --key %s)\n", encKey, out.MessageID, encKey)
	}
	for _, d := range out.Delivered {
		printDelivery(d)
	}
	if out.Link != nil {
		fmt.Printf("  link: %s (expires %s)\n", out.Link.URL, out.Link.ExpiresAt)
	}
	if out.CCOwner != "" {
		fmt.Printf("  cc_owner: %s\n", out.CCOwner)
	}
	fmt.Printf("  message: %s\n", out.MessageID)
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdMsg(args []string) error {
	fs := flag.NewFlagSet("msg", flag.ExitOnError)
	to := fs.String("to", "", "recipients, comma-separated")
	replyTo := fs.String("reply-to", "", "message id this replies to")
	subject := fs.String("subject", "", "subject")
	ccOwner := fs.Bool("cc-owner", false, "CC your human owner")
	idemFlag := fs.String("idempotency-key", "", "stable retry key (reuse after an uncertain send result)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *to == "" {
		return errors.New("usage: agenttransfer msg <text> --to a@b [--reply-to msg_...] [--idempotency-key k]")
	}
	idem, err := prepareIdempotencyKey(*idemFlag)
	if err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	req := map[string]any{"to": splitComma(*to), "note": strings.Join(pos, " ")}
	if *replyTo != "" {
		req["reply_to"] = *replyTo
	}
	if *subject != "" {
		req["subject"] = *subject
	}
	if *ccOwner {
		req["cc_owner"] = true
	}
	var out struct {
		MessageID string           `json:"message_id"`
		Delivered []map[string]any `json:"delivered"`
	}
	if err := a.jsonIdempotent("/v1/send", req, &out, idem); err != nil {
		return sendFailureError(err, a.base, idem, "", "", "--idempotency-key "+idem, req)
	}
	for _, d := range out.Delivered {
		printDelivery(d)
	}
	fmt.Printf("  message: %s\n", out.MessageID)
	return nil
}

func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	wait := fs.Int("wait", 0, "long-poll up to N seconds")
	all := fs.Bool("all", false, "include read messages")
	asJSON := fs.Bool("json", false, "raw JSON")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	path := "/v1/inbox?unread=1"
	if *all {
		path = "/v1/inbox"
	}
	if *wait > 0 {
		path = fmt.Sprintf("/v1/inbox/wait?timeout=%d", *wait)
	}
	var out struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := a.json("GET", path, nil, &out); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(out.Messages)
	}
	if len(out.Messages) == 0 {
		fmt.Println("inbox empty")
		return nil
	}
	for _, m := range out.Messages {
		fmt.Printf("%v  %v  %v\n", m["id"], m["from"], m["subject"])
		if t, _ := m["text"].(string); t != "" {
			fmt.Printf("    %s\n", firstLine(t))
		}
		if offer, ok := m["offer"].(map[string]any); ok {
			size := int64(0)
			if f, ok := offer["size"].(float64); ok {
				size = int64(f)
			}
			fmt.Printf("    ↳ file %v (%d bytes) — agenttransfer get %v\n", offer["name"], size, m["id"])
		}
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len(s) > 100 {
		s = s[:100] + "…"
	}
	return s
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	out := fs.String("o", "", "output path (default: original filename)")
	key := fs.String("key", "", "decryption key for a --encrypt'd file (atk_...)")
	sealedFlag := fs.Bool("seal", false, "force sealed decryption with your identity (auto-detected for msg_ offers)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer get <msg_...|share-url|sha256:...> [-o path] [--key atk_...]")
	}
	ref := pos[0]
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	a := newAPI(cfg)

	var url, wantSHA, name, encMode, markRead string
	switch {
	case strings.HasPrefix(ref, "msg_"):
		var m map[string]any
		if err := a.json("GET", "/v1/inbox/"+ref, nil, &m); err != nil {
			return err
		}
		offer, ok := m["offer"].(map[string]any)
		if !ok {
			return errors.New("message has no file offer")
		}
		url, _ = offer["url"].(string)
		wantSHA, _ = offer["sha256"].(string)
		name, _ = offer["name"].(string)
		encMode, _ = offer["enc_mode"].(string) // "", "symmetric", or "sealed"
		markRead = ref                          // marked read only on success, below
	case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"):
		url = ref
	case strings.HasPrefix(ref, "sha256:") || len(ref) == 64:
		sha := strings.TrimPrefix(ref, "sha256:")
		url = a.base + "/v1/files/" + sha + "/content"
		wantSHA = sha
	default:
		return fmt.Errorf("don't know how to fetch %q", ref)
	}

	// Decide decryption. --key forces symmetric; --seal or a sealed offer forces
	// sealed (identity); a symmetric offer needs --key.
	var ident *seal.Identity
	decryptSym := *key != ""
	decryptSealed := *sealedFlag || encMode == "sealed"
	if encMode == "symmetric" && *key == "" {
		return errors.New("this file is encrypted — supply the shared key with --key atk_...")
	}
	if decryptSym && decryptSealed {
		return errors.New("--key (symmetric) and --seal cannot combine")
	}
	if decryptSealed {
		ident, err = loadIdentity(cfg)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if sameOrigin(url, a.base) {
		req.Header.Set("Authorization", "Bearer "+a.key)
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return apiError(resp.StatusCode, data)
	}
	if name == "" {
		name = nameFromResponse(resp, url)
	}
	dest := *out
	explicitDest := dest != ""
	if dest == "" {
		dest = safeImplicitDownloadName(name)
	}
	if wantSHA == "" {
		wantSHA = strings.TrimPrefix(resp.Header.Get("X-Sha256"), "sha256:")
	}

	// Encrypted path: verify the ciphertext hash and decrypt to dest in one stream.
	if decryptSym || decryptSealed {
		got, err := verifyAndDecrypt(resp.Body, dest, wantSHA, *key, ident, explicitDest)
		if err != nil {
			return err
		}
		markReadIfSet(a, markRead)
		if wantSHA != "" {
			fmt.Printf("🔓 %s (decrypted; ciphertext sha256 verified: %s)\n", dest, got)
		} else {
			fmt.Printf("🔓 %s (decrypted; ciphertext sha256: %s — no expected hash to verify against)\n", dest, got)
		}
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".agenttransfer-*")
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	tmp.Close()
	if cerr != nil {
		os.Remove(tmp.Name())
		return cerr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(got, wantSHA) {
		os.Remove(tmp.Name())
		return fmt.Errorf("sha256 mismatch: got %s want %s — refusing the file", got, wantSHA)
	}
	if err := commitDownloadedFile(tmp.Name(), dest, explicitDest); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	markReadIfSet(a, markRead)
	// A file that arrived encrypted but wasn't decrypted (no --key/--seal, or an
	// offer whose enc_mode was stripped) is raw ciphertext — don't call it verified.
	if looksEncrypted(dest) {
		fmt.Printf("⚠ %s looks age-encrypted but no key was supplied — this is raw ciphertext.\n"+
			"  Re-run with --key atk_... (symmetric) or --seal (sealed to you).\n", dest)
		return nil
	}
	if wantSHA != "" {
		fmt.Printf("✓ %s (sha256 verified: %s)\n", dest, got)
	} else {
		fmt.Printf("✓ %s (sha256: %s — no expected hash to verify against)\n", dest, got)
	}
	return nil
}

// markReadIfSet marks an inbox message read after a successful download (so a
// failed get leaves it unread and resurfaceable).
func markReadIfSet(a *api, ref string) {
	if ref != "" {
		_ = a.json("POST", "/v1/inbox/"+url.PathEscape(ref)+"/read", map[string]any{}, nil)
	}
}

func nameFromResponse(resp *http.Response, url string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if name := strings.TrimSpace(params["filename"]); name != "" {
				return name
			}
		}
	}
	parts := strings.Split(strings.TrimRight(url, "/"), "/")
	n := parts[len(parts)-1]
	if n == "" || strings.ContainsAny(n, "?&") {
		n = "download.bin"
	}
	return n
}

func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	links := fs.Bool("links", false, "list share links instead of files")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	if *links {
		var out struct {
			Links []map[string]any `json:"links"`
		}
		if err := a.json("GET", "/v1/links", nil, &out); err != nil {
			return err
		}
		if len(out.Links) == 0 {
			fmt.Println("no links")
			return nil
		}
		for _, l := range out.Links {
			fmt.Printf("%-8v %-9v dl=%v  %v  %v\n", l["status"], l["once"], l["downloads"], l["url"], l["name"])
		}
		return nil
	}
	var out struct {
		Files        []map[string]any `json:"files"`
		StorageUsed  int64            `json:"storage_used"`
		StorageQuota int64            `json:"storage_quota"`
	}
	if err := a.json("GET", "/v1/files", nil, &out); err != nil {
		return err
	}
	for _, f := range out.Files {
		status := "kept"
		if claimed, _ := f["claimed"].(bool); !claimed {
			status = fmt.Sprintf("unclaimed (expires %v)", f["expires_at"])
		}
		fmt.Printf("%12v  %v  %v  [%s]\n", f["size"], f["sha256"], f["name"], status)
	}
	fmt.Printf("%d/%d bytes used\n", out.StorageUsed, out.StorageQuota)
	return nil
}

func cmdRm(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agenttransfer rm <sha256:...|link-token>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	ref := args[0]
	if strings.HasPrefix(ref, "sha256:") || len(ref) == 64 {
		sha := strings.TrimPrefix(ref, "sha256:")
		var out map[string]any
		if err := a.json("DELETE", "/v1/files/"+sha, nil, &out); err != nil {
			return err
		}
		fmt.Printf("✓ deleted %v entr(ies), revoked %v link(s)\n", out["deleted"], out["links_revoked"])
		return nil
	}
	if err := a.json("DELETE", "/v1/links/"+ref, nil, nil); err != nil {
		return err
	}
	fmt.Println("✓ link revoked (in-flight downloads severed)")
	return nil
}

// cmdWebhooks manages push endpoints: add <url>, ls, rm <id>.
func cmdWebhooks(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agenttransfer webhooks add <url> | ls | rm <id>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return errors.New("usage: agenttransfer webhooks add <https-url>")
		}
		var out struct {
			ID     string `json:"id"`
			URL    string `json:"url"`
			Secret string `json:"secret"`
		}
		if err := a.json("POST", "/v1/webhooks", map[string]any{"url": args[1]}, &out); err != nil {
			return err
		}
		fmt.Printf("✓ webhook %s → %s\n", out.ID, out.URL)
		fmt.Printf("  secret (shown once — verify Webhook-Signature with it): %s\n", out.Secret)
		return nil
	case "ls":
		var out struct {
			Webhooks []map[string]any `json:"webhooks"`
		}
		if err := a.json("GET", "/v1/webhooks", nil, &out); err != nil {
			return err
		}
		if len(out.Webhooks) == 0 {
			fmt.Println("no webhooks")
			return nil
		}
		for _, wh := range out.Webhooks {
			status := "enabled"
			if en, _ := wh["enabled"].(bool); !en {
				status = fmt.Sprintf("DISABLED (%v)", wh["disabled_reason"])
			}
			fmt.Printf("%v  %-9s fails=%v  %v\n", wh["id"], status, wh["fail_count"], wh["url"])
		}
		return nil
	case "rm":
		if len(args) < 2 {
			return errors.New("usage: agenttransfer webhooks rm <id>")
		}
		if err := a.json("DELETE", "/v1/webhooks/"+args[1], nil, nil); err != nil {
			return err
		}
		fmt.Println("✓ webhook removed")
		return nil
	}
	return fmt.Errorf("unknown webhooks subcommand %q (add|ls|rm)", args[0])
}

func cmdKeep(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agenttransfer keep <sha256:...>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	sha := strings.TrimPrefix(args[0], "sha256:")
	var out struct {
		Name      string `json:"name"`
		Claimed   bool   `json:"claimed"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := a.json("POST", "/v1/files/"+sha+"/keep", map[string]any{}, &out); err != nil {
		return err
	}
	if out.ExpiresAt != "" {
		fmt.Printf("✓ kept %s — retained until %s at your current storage tier\n", out.Name, out.ExpiresAt)
	} else {
		fmt.Printf("✓ kept %s — now persistent\n", out.Name)
	}
	return nil
}

func cmdLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	ttl := fs.String("ttl", "", "TTL (e.g. 3h, max 24h)")
	once := fs.Bool("once", false, "burn-after-read")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer link <sha256:...|name-in-folder> [--ttl 3h] [--once]")
	}
	a, err := client()
	if err != nil {
		return err
	}
	req := map[string]any{"file": pos[0]}
	if *ttl != "" {
		req["ttl"] = *ttl
	}
	if *once {
		req["once"] = true
	}
	var out map[string]any
	if err := a.json("POST", "/v1/links", req, &out); err != nil {
		return err
	}
	fmt.Printf("%v\n  expires %v  once=%v  sha256:%v\n", out["url"], out["expires_at"], out["once"], out["sha256"])
	return nil
}

func cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	note := fs.String("note", "", "what you want uploaded")
	ttl := fs.String("ttl", "", "page lifetime (max 24h)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	req := map[string]any{"note": *note}
	if *ttl != "" {
		req["ttl"] = *ttl
	}
	var out map[string]any
	if err := a.json("POST", "/v1/requests", req, &out); err != nil {
		return err
	}
	fmt.Printf("Send a human this one-time upload page:\n  %v\n  (expires %v)\n", out["upload_url"], out["expires_at"])
	return nil
}

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	verify := fs.Bool("verify", false, "verify signatures")
	asJSON := fs.Bool("json", false, "raw JSON")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	var out struct {
		Instance      string            `json:"instance"`
		ReceiptPubkey string            `json:"receipt_pubkey"`
		Receipts      []receipt.Receipt `json:"receipts"`
	}
	if err := a.json("GET", "/v1/receipts", nil, &out); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(out)
	}
	if *verify {
		pub, err := receipt.ParsePublicKey(out.ReceiptPubkey)
		if err != nil {
			return err
		}
		if err := receipt.VerifyChain(out.Receipts, pub, false); err != nil {
			return fmt.Errorf("VERIFICATION FAILED: %w", err)
		}
		fmt.Printf("✓ %d receipt signature(s) verified against %s\n", len(out.Receipts), out.Instance)
	}
	for _, r := range out.Receipts {
		fmt.Printf("%s  %s\n", r.TS, formatReceiptLine(r))
	}
	return nil
}

// formatReceiptLine renders a receipt with the arrow pointing the way the
// message or bytes actually flowed.
func formatReceiptLine(r receipt.Receipt) string {
	var flow string
	switch {
	case r.Target == "":
		flow = r.Actor
	case r.Action == receipt.ActionReceived:
		flow = r.Actor + " ← " + r.Target
	case r.Action == receipt.ActionDownloaded:
		flow = r.Target + " of " + r.Actor
	default:
		flow = r.Actor + " → " + r.Target
	}
	line := fmt.Sprintf("%-11s %s", r.Action, flow)
	if r.SHA256 != "" {
		short := r.SHA256
		if len(short) > 12 {
			short = short[:12] + "…"
		}
		line += "  sha256:" + short
	}
	return line
}

func cmdVerify(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agenttransfer verify <receipts.jsonl|instance-url> (full-chain verification needs the admin export)")
	}
	src := args[0]
	var rs []receipt.Receipt
	var pub string

	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		base := strings.TrimRight(src, "/")
		verifyAPI := newAPI(clientConfig{URL: base})
		req, err := http.NewRequest("GET", base+"/.well-known/agenttransfer", nil)
		if err != nil {
			return err
		}
		resp, err := verifyAPI.hc.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 300 {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return apiError(resp.StatusCode, data)
		}
		var wk struct {
			ReceiptPubkey string `json:"receipt_pubkey"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&wk); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()
		pub = wk.ReceiptPubkey
		tok := os.Getenv("AGENTTRANSFER_ADMIN_TOKEN")
		if tok == "" {
			return errors.New("set AGENTTRANSFER_ADMIN_TOKEN to fetch the full export from an instance")
		}
		verifyAPI.key = tok
		resp2, err := verifyAPI.req("GET", "/v1/receipts/export", nil, "")
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode >= 300 {
			data, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
			return apiError(resp2.StatusCode, data)
		}
		rs, err = receipt.ReadJSONL(resp2.Body)
		if err != nil {
			return err
		}
	} else {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		rs, err = receipt.ReadJSONL(f)
		if err != nil {
			return err
		}
		if len(rs) > 0 {
			fmt.Printf("instance: %s\n", rs[0].Instance)
		}
		pub = os.Getenv("AGENTTRANSFER_PUBKEY")
		if pub == "" {
			return errors.New("set AGENTTRANSFER_PUBKEY=ed25519:... (from /.well-known/agenttransfer) to verify a file export")
		}
	}

	pubKey, err := receipt.ParsePublicKey(pub)
	if err != nil {
		return err
	}
	// Exports are emitted in chain order (insertion sequence). Never re-sort
	// by timestamp: wall clocks aren't monotonic, and a reorder would report
	// tampering on a perfectly valid chain.
	if err := receipt.VerifyChain(rs, pubKey, true); err != nil {
		return fmt.Errorf("VERIFICATION FAILED: %w", err)
	}
	fmt.Printf("✓ provided genesis-anchored export has %d valid signature(s) and no internal gaps; completeness requires a trusted checkpoint\n", len(rs))
	return nil
}

func cmdRotateKey(args []string) error {
	if envAuthActive() {
		return errors.New("rotate-key refuses environment-backed credentials because it cannot update AGENTTRANSFER_KEY; unset AGENTTRANSFER_URL/AGENTTRANSFER_KEY and log in with the saved config first")
	}
	c, err := readFileConfig()
	if err != nil {
		return err
	}
	if c.URL == "" || c.APIKey == "" {
		return errors.New("saved config is incomplete; log in again before rotating")
	}
	// The current API cannot stage a caller-generated replacement key. Verify
	// that an atomic config replacement succeeds before asking the server to
	// invalidate the old key, minimizing the only remaining failure window.
	if err := saveConfig(c); err != nil {
		return fmt.Errorf("config is not safely writable; key was not rotated: %w", err)
	}
	a := newAPI(c)
	var out struct {
		APIKey string `json:"api_key"`
	}
	if err := a.json("POST", "/v1/agents/self/rotate_key", map[string]any{}, &out); err != nil {
		return err
	}
	if strings.TrimSpace(out.APIKey) == "" {
		return errors.New("rotation response omitted the new API key; the server may already have invalidated the old key")
	}
	// The old key is now dead. Persist atomically and, if that unexpectedly
	// fails after the preflight, return the one-time replacement in the error.
	c.APIKey = out.APIKey
	if err := saveConfig(c); err != nil {
		return fmt.Errorf("KEY ROTATED BUT NOT SAVED: store this replacement now: %s (%w)", out.APIKey, err)
	}
	fmt.Printf("✓ key rotated and saved\n  new key: %s\n", out.APIKey)
	return nil
}

func envAuthActive() bool {
	return strings.TrimSpace(os.Getenv("AGENTTRANSFER_URL")) != "" && strings.TrimSpace(os.Getenv("AGENTTRANSFER_KEY")) != ""
}

// cmdDeleteSelf removes the logged-in agent. It clears the saved login only
// when that file supplied the credentials; env-auth may intentionally point at
// a different temporary agent and must never erase an unrelated saved login.
func cmdDeleteSelf(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	a := newAPI(cfg)
	var out map[string]any
	if err := a.json("DELETE", "/v1/agents/self", nil, &out); err != nil {
		return err
	}
	fmt.Printf("✓ deleted %v — your key is dead; receipts are kept on the instance\n", out["deleted"])
	if !envAuthActive() {
		if err := clearDeletedLogin(cfg); err != nil {
			return fmt.Errorf("agent was deleted, but local login cleanup failed: %w", err)
		}
	}
	return nil
}

func cmdAgents(args []string) error {
	if len(args) < 1 || (args[0] != "create" && args[0] != "rm") {
		return errors.New("usage: agenttransfer agents create --name n [--owner e] [--url u] [--admin-token t]\n" +
			"       agenttransfer agents rm <agent_id> [--url u] [--admin-token t]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("agents "+sub, flag.ExitOnError)
	name := fs.String("name", "", "agent name (becomes the address localpart)")
	owner := fs.String("owner", "", "owner email")
	url := fs.String("url", "", "instance URL (default: logged-in instance)")
	adminToken := fs.String("admin-token", os.Getenv("AGENTTRANSFER_ADMIN_TOKEN"), "admin token")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	base := *url
	if base == "" {
		if c, err := loadConfig(); err == nil {
			base = c.URL
		}
	}
	if base == "" {
		return errors.New("--url is required (no login found)")
	}
	if *adminToken == "" {
		return errors.New("--admin-token (or AGENTTRANSFER_ADMIN_TOKEN) is required")
	}
	a := newAPI(clientConfig{URL: strings.TrimRight(base, "/"), APIKey: *adminToken})
	a.hc.Timeout = 30 * time.Second

	if sub == "rm" {
		if len(pos) < 1 {
			return errors.New("usage: agenttransfer agents rm <agent_id>")
		}
		var out map[string]any
		if err := a.json("DELETE", "/v1/agents/"+pos[0], nil, &out); err != nil {
			return err
		}
		fmt.Printf("✓ deleted %v (severed %v link(s); its receipts are kept)\n", out["deleted"], out["links_severed"])
		return nil
	}

	if *name == "" {
		return errors.New("--name is required")
	}
	var out map[string]any
	if err := a.json("POST", "/v1/agents", map[string]any{"name": *name, "owner_email": *owner}, &out); err != nil {
		return err
	}
	return printJSON(out)
}

// card is an agent's public discovery profile, decoded from the wire form the
// server returns (store.Card). The CLI never imports server/store types.
type card struct {
	Name          string   `json:"name"`
	Pubkey        string   `json:"pubkey"`
	Description   string   `json:"description"`
	Capabilities  []string `json:"capabilities"`
	PublicContact string   `json:"public_contact"`
	Verified      struct {
		Tier     string `json:"tier"`
		Instance string `json:"instance"`
		Basis    string `json:"basis"`
	} `json:"verified"`
	Listed    bool  `json:"listed"`
	UpdatedAt int64 `json:"updated_at"`
}

// cmdDirectory lists agents that opted into discovery — how an agent finds peers
// by what they can do.
func cmdDirectory(args []string) error {
	fs := flag.NewFlagSet("directory", flag.ExitOnError)
	capability := fs.String("capability", "", "filter to agents advertising this capability tag")
	limit := fs.Int("limit", 0, "max agents to list (server caps at 200)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	q := url.Values{}
	if *capability != "" {
		q.Set("capability", *capability)
	}
	if *limit > 0 {
		q.Set("limit", strconv.Itoa(*limit))
	}
	path := "/v1/directory"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out struct {
		Agents []card `json:"agents"`
		Count  int    `json:"count"`
	}
	if err := a.json("GET", path, nil, &out); err != nil {
		return err
	}
	if out.Count == 0 {
		fmt.Println("no agents listed in the directory")
		return nil
	}
	for _, ag := range out.Agents {
		parts := []string{ag.Name}
		if ag.Description != "" {
			parts = append(parts, ag.Description)
		}
		if len(ag.Capabilities) > 0 {
			parts = append(parts, strings.Join(ag.Capabilities, ", "))
		}
		if ag.Verified.Tier != "" {
			parts = append(parts, "verified: "+ag.Verified.Tier+" ("+ag.Verified.Basis+")")
		}
		if ag.PublicContact != "" {
			parts = append(parts, "contact: "+ag.PublicContact)
		}
		fmt.Println(strings.Join(parts, " — "))
	}
	return nil
}

// cmdCard shows another agent's public card (404 if it's unlisted or absent).
func cmdCard(args []string) error {
	fs := flag.NewFlagSet("card", flag.ExitOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer card <name>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var c card
	if err := a.json("GET", "/v1/agents/"+url.PathEscape(pos[0])+"/card", nil, &c); err != nil {
		return err
	}
	fmt.Println(c.Name)
	if c.Description != "" {
		fmt.Printf("  %s\n", c.Description)
	}
	if len(c.Capabilities) > 0 {
		fmt.Printf("  capabilities: %s\n", strings.Join(c.Capabilities, ", "))
	}
	if c.Pubkey != "" {
		fmt.Printf("  pubkey: %s\n", c.Pubkey)
	}
	if c.Verified.Tier != "" {
		fmt.Printf("  verified: %s (basis: %s; instance: %s)\n", c.Verified.Tier, c.Verified.Basis, c.Verified.Instance)
	}
	if c.PublicContact != "" {
		fmt.Printf("  contact: %s\n", c.PublicContact)
	}
	return nil
}

// cmdCardSet publishes/updates the caller's own discovery card. It is a full
// upsert (PUT): capabilities and listed are replaced with what's supplied here.
func cmdCardSet(args []string) error {
	fs := flag.NewFlagSet("card-set", flag.ExitOnError)
	description := fs.String("description", "", "one-line description of what your agent does")
	capabilities := fs.String("capabilities", "", "comma-separated capability tags")
	listed := fs.Bool("listed", false, "opt into the public directory")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*description) == "" {
		return errors.New(`usage: agenttransfer card-set --description "..." [--capabilities a,b,c] [--listed]`)
	}
	a, err := client()
	if err != nil {
		return err
	}
	req := map[string]any{
		"description":  *description,
		"capabilities": splitComma(*capabilities),
		"listed":       *listed,
	}
	var c card
	if err := a.json("PUT", "/v1/agents/self/card", req, &c); err != nil {
		return err
	}
	state := "unlisted (not discoverable)"
	if c.Listed {
		state = "listed in the directory"
	}
	fmt.Printf("✓ card published — %s\n", state)
	if c.Description != "" {
		fmt.Printf("  %s\n", c.Description)
	}
	if len(c.Capabilities) > 0 {
		fmt.Printf("  capabilities: %s\n", strings.Join(c.Capabilities, ", "))
	}
	return nil
}
