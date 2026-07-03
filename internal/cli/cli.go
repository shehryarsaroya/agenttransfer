// Package cli implements the agenttransfer command-line client (and the demo
// and doctor subcommands). The CLI is a thin wrapper over the same REST API
// agents use — nothing here can't be done with curl.
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
)

// clientConfig is what `agenttransfer login` writes.
type clientConfig struct {
	URL    string `json:"url"`
	APIKey string `json:"api_key"`
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
	return c, nil
}

// api is a tiny authenticated HTTP client.
type api struct {
	base string
	key  string
	hc   *http.Client
}

func newAPI(c clientConfig) *api {
	return &api{base: strings.TrimRight(c.URL, "/"), key: c.APIKey, hc: &http.Client{Timeout: 10 * time.Minute}}
}

func (a *api) req(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.key)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return a.hc.Do(req)
}

func (a *api) json(method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(buf))
	}
	resp, err := a.req(method, path, body, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
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
  agenttransfer demo                  30-second local end-to-end demo
  agenttransfer doctor                self-host preflight checks

client:
  agenttransfer signup <url> --name n --owner you@example.com   create your own agent + log in
  agenttransfer login <url> --key K   store credentials (in your OS user-config dir)
  agenttransfer whoami
  agenttransfer put <file> [--share] [--ttl 3h] [--once]        upload into your folder
  agenttransfer send <file> --to a@b[,c@d] [--note s] [--subject s] [--ttl 3h] [--once] [--cc-owner]
  agenttransfer msg <text> --to a@b [--reply-to msg_...] [--subject s] [--cc-owner]
  agenttransfer inbox [--wait N] [--all] [--json]
  agenttransfer get <msg_...|url|sha256:...> [-o path]
  agenttransfer ls [--links]
  agenttransfer rm <sha256:...|link-token>
  agenttransfer keep <sha256:...>
  agenttransfer link <sha256:...|name-in-folder> [--ttl 3h] [--once]
  agenttransfer request [--note s] [--ttl 24h]
  agenttransfer log [--verify] [--json]
  agenttransfer verify <receipts.jsonl|instance-url>
  agenttransfer rotate-key
  agenttransfer delete-self          delete your own agent (receipts are kept)
  agenttransfer agents create --name n [--owner e] [--url u] [--admin-token t]
  agenttransfer agents rm <agent_id> [--url u] [--admin-token t]   delete an agent (keeps its receipts)

Flags may go before or after positional arguments.
env: AGENTTRANSFER_URL + AGENTTRANSFER_KEY override the config file;
     AGENTTRANSFER_ADMIN_TOKEN for "agents create" / "verify <url>";
     AGENTTRANSFER_PUBKEY (ed25519:...) for "verify <file.jsonl>".
`)
}

// cmdSignup self-registers an agent on an open-signup instance (no admin
// token needed) and logs in as it — the one-command onboarding path.
func cmdSignup(args []string) error {
	fs := flag.NewFlagSet("signup", flag.ExitOnError)
	name := fs.String("name", "", "agent name (becomes the address localpart)")
	owner := fs.String("owner", "", "your human email (required; verifies outbound email later)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *name == "" || *owner == "" {
		return errors.New("usage: agenttransfer signup <url> --name my-agent --owner you@example.com")
	}
	base := strings.TrimRight(pos[0], "/")

	a := &api{base: base, hc: &http.Client{Timeout: 30 * time.Second}}
	var out struct {
		Name         string `json:"name"`
		Email        string `json:"email"`
		APIKey       string `json:"api_key"`
		Verification string `json:"verification"`
		Note         string `json:"note"`
	}
	if err := a.json("POST", "/v1/agents", map[string]any{"name": *name, "owner_email": *owner}, &out); err != nil {
		return err
	}

	c := clientConfig{URL: base, APIKey: out.APIKey}
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	buf, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		return err
	}

	fmt.Printf("✓ you are %s\n", out.Email)
	if out.Note != "" {
		fmt.Printf("  note: %s\n", out.Note)
	}
	fmt.Printf("  api key saved to %s (shown once by the server — keep it safe)\n", p)
	switch out.Verification {
	case "sent":
		fmt.Printf("  a verification link was emailed to %s — confirm it to unlock sending email to humans\n", *owner)
	case "pending":
		fmt.Printf("  outbound email to humans stays locked until the operator verifies %s\n", *owner)
	}
	fmt.Println("  everything else works now: put, send (to agents), inbox, get")
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
		Email string `json:"email"`
	}
	if err := a.json("GET", "/v1/whoami", nil, &who); err != nil {
		return fmt.Errorf("login check failed: %w", err)
	}
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	buf, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		return err
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
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer put <file> [--share] [--ttl 3h] [--once]")
	}
	a, err := client()
	if err != nil {
		return err
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	defer f.Close()
	name := filepath.Base(pos[0])

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
	path := "/v1/files/" + name
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := a.req("PUT", path, f, "application/octet-stream")
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
	fmt.Printf("✓ %s (%d bytes) sha256:%s\n", name, up.Size, up.SHA256)
	if up.Link != nil {
		fmt.Printf("  link: %s (expires %s, once=%v)\n", up.Link.URL, up.Link.ExpiresAt, up.Link.Once)
	}
	return nil
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "recipients, comma-separated")
	note := fs.String("note", "", "message text")
	subject := fs.String("subject", "", "subject")
	ttl := fs.String("ttl", "", "link TTL (e.g. 3h, max 24h)")
	once := fs.Bool("once", false, "burn-after-read link")
	ccOwner := fs.Bool("cc-owner", false, "CC your human owner")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *to == "" {
		return errors.New("usage: agenttransfer send <file> --to a@b[,c@d] [--note ...]")
	}
	path := pos[0]
	a, err := client()
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	name := filepath.Base(path)
	resp, err := a.req("PUT", "/v1/files/"+name, f, "application/octet-stream")
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
	fmt.Printf("✓ uploaded %s (%d bytes) sha256:%s\n", name, up.Size, up.SHA256)

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
		"to":   splitComma(*to),
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
	if err := a.json("POST", "/v1/send", req, &out); err != nil {
		return err
	}
	for _, d := range out.Delivered {
		fmt.Printf("✓ delivered to %v via %v\n", d["to"], d["via"])
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
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || *to == "" {
		return errors.New("usage: agenttransfer msg <text> --to a@b [--reply-to msg_...]")
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
	if err := a.json("POST", "/v1/send", req, &out); err != nil {
		return err
	}
	for _, d := range out.Delivered {
		fmt.Printf("✓ delivered to %v via %v\n", d["to"], d["via"])
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
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer get <msg_...|share-url|sha256:...> [-o path]")
	}
	ref := pos[0]
	a, err := client()
	if err != nil {
		return err
	}

	var url, wantSHA, name string
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
		defer a.json("POST", "/v1/inbox/"+ref+"/read", map[string]any{}, nil)
	case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"):
		url = ref
	case strings.HasPrefix(ref, "sha256:") || len(ref) == 64:
		sha := strings.TrimPrefix(ref, "sha256:")
		url = a.base + "/v1/files/" + sha + "/content"
		wantSHA = sha
	default:
		return fmt.Errorf("don't know how to fetch %q", ref)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if strings.HasPrefix(url, a.base) {
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
	if dest == "" {
		dest = name
	}
	if wantSHA == "" {
		wantSHA = strings.TrimPrefix(resp.Header.Get("X-Sha256"), "sha256:")
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
	if err := os.Rename(tmp.Name(), dest); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if wantSHA != "" {
		fmt.Printf("✓ %s (sha256 verified: %s)\n", dest, got)
	} else {
		fmt.Printf("✓ %s (sha256: %s — no expected hash to verify against)\n", dest, got)
	}
	return nil
}

func nameFromResponse(resp *http.Response, url string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if i := strings.Index(cd, `filename="`); i >= 0 {
			rest := cd[i+len(`filename="`):]
			if j := strings.IndexByte(rest, '"'); j > 0 {
				return rest[:j]
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

func cmdKeep(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agenttransfer keep <sha256:...>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	sha := strings.TrimPrefix(args[0], "sha256:")
	var out map[string]any
	if err := a.json("POST", "/v1/files/"+sha+"/keep", map[string]any{}, &out); err != nil {
		return err
	}
	fmt.Printf("✓ kept %v — it's now persistent\n", out["name"])
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
		line += "  sha256:" + r.SHA256[:12] + "…"
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
		resp, err := http.Get(base + "/.well-known/agenttransfer")
		if err != nil {
			return err
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
		req, _ := http.NewRequest("GET", base+"/v1/receipts/export", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp2, err := http.DefaultClient.Do(req)
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
	fmt.Printf("✓ full chain verified: %d receipts, signatures valid, no gaps, no tampering\n", len(rs))
	return nil
}

func cmdRotateKey(args []string) error {
	a, err := client()
	if err != nil {
		return err
	}
	var out struct {
		APIKey string `json:"api_key"`
	}
	if err := a.json("POST", "/v1/agents/self/rotate_key", map[string]any{}, &out); err != nil {
		return err
	}
	// Persist the new key immediately — the old one is already dead.
	c, _ := loadConfig()
	c.APIKey = out.APIKey
	p, err := configPath()
	if err == nil {
		buf, _ := json.MarshalIndent(c, "", "  ")
		_ = os.WriteFile(p, buf, 0o600)
	}
	fmt.Printf("✓ key rotated and saved\n  new key: %s\n", out.APIKey)
	return nil
}

// cmdDeleteSelf removes the logged-in agent and clears the local config.
func cmdDeleteSelf(args []string) error {
	a, err := client()
	if err != nil {
		return err
	}
	var out map[string]any
	if err := a.json("DELETE", "/v1/agents/self", nil, &out); err != nil {
		return err
	}
	fmt.Printf("✓ deleted %v — your key is dead; receipts are kept on the instance\n", out["deleted"])
	if p, err := configPath(); err == nil {
		_ = os.Remove(p)
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
	a := &api{base: strings.TrimRight(base, "/"), key: *adminToken, hc: &http.Client{Timeout: 30 * time.Second}}

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
