package cli

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// repeatedFlag makes --env and --command naturally repeatable while still
// working with parseArgs, which permits flags before or after positionals.
type repeatedFlag []string

func (v *repeatedFlag) String() string { return strings.Join(*v, ",") }
func (v *repeatedFlag) Set(s string) error {
	*v = append(*v, s)
	return nil
}

type appDeployOptions struct {
	Kind       string
	Image      string
	Port       int
	Env        map[string]string
	Command    []string
	SPA        bool
	HealthPath string
}

type appDeployRequest struct {
	Kind       string            `json:"kind"`
	Source     string            `json:"source,omitempty"`
	Image      string            `json:"image,omitempty"`
	Port       int               `json:"port,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Command    []string          `json:"command,omitempty"`
	SPA        bool              `json:"spa,omitempty"`
	HealthPath string            `json:"health_path,omitempty"`
}

func cmdAppDeploy(args []string) error {
	fs := flag.NewFlagSet("app-deploy", flag.ExitOnError)
	kind := fs.String("kind", "", "deployment kind: static or container (inferred when omitted)")
	port := fs.Int("port", 8080, "container HTTP port")
	image := fs.String("image", "", "OCI image to run instead of uploading local source")
	spa := fs.Bool("spa", false, "serve index.html for unknown static-site routes")
	healthPath := fs.String("health-path", "/", "container path that must return 2xx before activation")
	var envFlags, commandFlags repeatedFlag
	fs.Var(&envFlags, "env", "environment variable KEY=VALUE (repeatable)")
	fs.Var(&commandFlags, "command", "container argv item (repeatable), or one JSON string array")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: agenttransfer app-deploy <dir|archive> [flags], or app-deploy --image IMAGE [flags]")
	}
	input := ""
	if len(pos) == 1 {
		input = pos[0]
	}
	env, err := parseAppEnv(envFlags)
	if err != nil {
		return err
	}
	command, err := parseAppCommand(commandFlags)
	if err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	raw, warning, err := deployApp(a, input, appDeployOptions{
		Kind: *kind, Image: *image, Port: *port, Env: env, Command: command, SPA: *spa, HealthPath: *healthPath,
	})
	if err != nil {
		return err
	}
	fmt.Println("✓ deployment accepted")
	if len(raw) > 0 {
		fmt.Println(prettyRawJSON(raw))
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	return nil
}

func cmdAppStatus(args []string) error {
	fs := flag.NewFlagSet("app-status", flag.ExitOnError)
	if pos, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("usage: agenttransfer app-status")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := a.json("GET", "/v1/apps/self", nil, &raw); err != nil {
		return err
	}
	fmt.Println(prettyRawJSON(raw))
	return nil
}

func cmdAppLogs(args []string) error {
	fs := flag.NewFlagSet("app-logs", flag.ExitOnError)
	tail := fs.Int("tail", 200, "number of recent log lines (1-2000)")
	if pos, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("usage: agenttransfer app-logs [--tail N]")
	}
	if *tail < 1 || *tail > 2000 {
		return errors.New("--tail must be between 1 and 2000")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := a.json("GET", "/v1/apps/self/logs?tail="+strconv.Itoa(*tail), nil, &raw); err != nil {
		return err
	}
	printAppLogs(raw)
	return nil
}

func cmdAppStop(args []string) error {
	fs := flag.NewFlagSet("app-stop", flag.ExitOnError)
	if pos, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("usage: agenttransfer app-stop")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := a.json("POST", "/v1/apps/self/stop", map[string]any{}, &raw); err != nil {
		return err
	}
	fmt.Println("✓ app stopped")
	if len(raw) > 0 {
		fmt.Println(prettyRawJSON(raw))
	}
	return nil
}

func cmdAppRemove(args []string) error {
	fs := flag.NewFlagSet("app-rm", flag.ExitOnError)
	purge := fs.Bool("purge-data", false, "also delete the app's persistent data")
	if pos, err := parseArgs(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("usage: agenttransfer app-rm [--purge-data]")
	}
	a, err := client()
	if err != nil {
		return err
	}
	q := url.Values{"purge_data": []string{strconv.FormatBool(*purge)}}
	var raw json.RawMessage
	if err := a.json("DELETE", "/v1/apps/self?"+q.Encode(), nil, &raw); err != nil {
		return err
	}
	fmt.Println("✓ app removed")
	if len(raw) > 0 {
		fmt.Println(prettyRawJSON(raw))
	}
	return nil
}

// deployApp packages input when it is a directory, stages the resulting
// archive in the ordinary file API, creates the app deployment, then removes
// that temporary folder reference. The deployment takes its own blob reference
// before the cleanup request returns, so the source remains GC-reachable.
func deployApp(a *api, input string, opts appDeployOptions) (raw json.RawMessage, warning string, err error) {
	req, err := normalizeAppDeploy(input, opts)
	if err != nil {
		return nil, "", err
	}
	var stagedSHA, stagedName string
	if req.Image == "" {
		localPath := input
		info, err := os.Lstat(localPath)
		if err != nil {
			return nil, "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, "", errors.New("deployment source itself may not be a symlink")
		}
		if info.IsDir() {
			localPath, err = archiveAppDirectory(localPath)
			if err != nil {
				return nil, "", err
			}
			defer os.Remove(localPath)
		} else if !info.Mode().IsRegular() {
			return nil, "", errors.New("deployment source must be a directory or regular archive file")
		}
		stagedSHA, stagedName, err = uploadAppSource(a, localPath)
		if err != nil {
			return nil, "", fmt.Errorf("stage deployment source: %w", err)
		}
		req.Source = "sha256:" + stagedSHA
		defer func() {
			cleanupPath := "/v1/files/" + url.PathEscape(stagedSHA) + "?entry=" + url.QueryEscape(stagedName)
			if cleanupErr := a.json("DELETE", cleanupPath, nil, nil); cleanupErr != nil {
				if err != nil {
					err = fmt.Errorf("%w (temporary deployment entry cleanup also failed: %v)", err, cleanupErr)
				} else {
					warning = "deployment was accepted, but its temporary folder entry could not be removed: " + cleanupErr.Error()
				}
			}
		}()
	}
	if err := a.jsonLong("POST", "/v1/apps/self/deploy", req, &raw); err != nil {
		return nil, "", err
	}
	return raw, warning, nil
}

func normalizeAppDeploy(input string, opts appDeployOptions) (appDeployRequest, error) {
	input = strings.TrimSpace(input)
	opts.Kind = strings.ToLower(strings.TrimSpace(opts.Kind))
	opts.Image = strings.TrimSpace(opts.Image)
	if input != "" && opts.Image != "" {
		return appDeployRequest{}, errors.New("provide either a local directory/archive or --image, not both")
	}
	if input == "" && opts.Image == "" {
		return appDeployRequest{}, errors.New("provide a local directory/archive or --image IMAGE")
	}
	if opts.Kind == "" {
		if opts.Image != "" {
			opts.Kind = "container"
		} else {
			opts.Kind = "static"
		}
	}
	if opts.Kind != "static" && opts.Kind != "container" {
		return appDeployRequest{}, errors.New("--kind must be static or container")
	}
	if opts.Image != "" && opts.Kind != "container" {
		return appDeployRequest{}, errors.New("--image requires --kind container")
	}
	if opts.Kind == "static" && (len(opts.Env) > 0 || len(opts.Command) > 0) {
		return appDeployRequest{}, errors.New("--env and --command require --kind container")
	}
	if opts.Kind == "container" && opts.SPA {
		return appDeployRequest{}, errors.New("--spa is only valid for --kind static")
	}
	if opts.Kind == "static" && opts.HealthPath != "" && opts.HealthPath != "/" {
		return appDeployRequest{}, errors.New("--health-path is only valid for --kind container")
	}
	if len(opts.Env) > 64 {
		return appDeployRequest{}, errors.New("at most 64 environment variables are allowed")
	}
	for key, value := range opts.Env {
		if !validEnvName(key) || strings.ContainsRune(value, '\x00') {
			return appDeployRequest{}, fmt.Errorf("invalid environment variable %q", key)
		}
	}
	if len(opts.Command) > 64 {
		return appDeployRequest{}, errors.New("command has too many arguments (max 64)")
	}
	for _, arg := range opts.Command {
		if strings.ContainsRune(arg, '\x00') {
			return appDeployRequest{}, errors.New("command arguments may not contain NUL bytes")
		}
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return appDeployRequest{}, errors.New("--port must be between 1 and 65535")
	}
	if opts.Kind == "container" {
		if opts.HealthPath == "" {
			opts.HealthPath = "/"
		}
		if !validAppHealthPath(opts.HealthPath) {
			return appDeployRequest{}, errors.New("--health-path must be an absolute path up to 256 bytes without query, fragment, backslash, or control characters")
		}
	}
	return appDeployRequest{
		Kind: opts.Kind, Image: opts.Image, Port: opts.Port, Env: opts.Env,
		Command: opts.Command, SPA: opts.SPA, HealthPath: opts.HealthPath,
	}, nil
}

func validAppHealthPath(value string) bool {
	if value == "" || len(value) > 256 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#\\") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func parseAppEnv(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok || !validEnvName(key) {
			return nil, fmt.Errorf("invalid --env %q: expected KEY=VALUE with a shell-style variable name", value)
		}
		out[key] = val
	}
	return out, nil
}

func validEnvName(s string) bool {
	if s == "" || !(s[0] == '_' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func parseAppCommand(values []string) ([]string, error) {
	if len(values) == 1 && strings.HasPrefix(strings.TrimSpace(values[0]), "[") {
		var out []string
		if err := json.Unmarshal([]byte(values[0]), &out); err != nil {
			return nil, fmt.Errorf("--command JSON must be an array of strings: %w", err)
		}
		if len(out) == 0 {
			return nil, errors.New("--command JSON array cannot be empty")
		}
		return out, nil
	}
	return append([]string(nil), values...), nil
}

func uploadAppSource(a *api, path string) (sha, name string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	name = fmt.Sprintf(".agenttransfer-deploy-%d-%s", time.Now().UnixNano(), filepath.Base(path))
	resp, err := a.req("PUT", "/v1/files/"+url.PathEscape(name), f, "application/octet-stream")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if readErr != nil {
		return "", "", readErr
	}
	if resp.StatusCode >= 300 {
		return "", "", apiError(resp.StatusCode, data)
	}
	var up struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &up); err != nil {
		return "", "", err
	}
	decoded, err := hex.DecodeString(up.SHA256)
	if err != nil || len(decoded) != 32 {
		return "", "", errors.New("upload response contained an invalid sha256")
	}
	return strings.ToLower(up.SHA256), name, nil
}

// archiveAppDirectory builds a deterministic gzip-compressed tarball. It does
// not follow symlinks, rejects special files, and omits every .git directory so
// a deploy cannot accidentally package repository history or escape its root.
func archiveAppDirectory(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	out, err := os.CreateTemp("", "agenttransfer-app-*.tar.gz")
	if err != nil {
		return "", err
	}
	name := out.Name()
	cleanup := func(e error) (string, error) {
		out.Close()
		os.Remove(name)
		return "", e
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if part == ".git" {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("deployment source contains symlink %q; symlinks are not packaged", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("deployment source contains unsupported special file %q", rel)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		hdr.Mode = int64(info.Mode().Perm())
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		hdr.ModTime = time.Unix(0, 0).UTC()
		hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
		hdr.Format = tar.FormatPAX
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		openedInfo, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			f.Close()
			return fmt.Errorf("deployment source changed while packaging %q", rel)
		}
		n, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return fmt.Errorf("deployment source changed size while packaging %q", rel)
		}
		return nil
	})
	if walkErr != nil {
		tw.Close()
		gz.Close()
		return cleanup(walkErr)
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		return cleanup(err)
	}
	if err := gz.Close(); err != nil {
		return cleanup(err)
	}
	if err := out.Sync(); err != nil {
		return cleanup(err)
	}
	if err := out.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func prettyRawJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return strings.TrimSpace(string(raw))
	}
	redactAppEnv(v)
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return strings.TrimSpace(string(raw))
	}
	return string(b)
}

// redactAppEnv is defense in depth: deployment responses should expose only
// env_keys, but an older server may echo config.env. Never print those values
// into a terminal or an MCP model context.
func redactAppEnv(v any) {
	switch x := v.(type) {
	case []any:
		for _, child := range x {
			redactAppEnv(child)
		}
	case map[string]any:
		for key, child := range x {
			if strings.EqualFold(key, "env") {
				if values, ok := child.(map[string]any); ok {
					redacted := make(map[string]any, len(values))
					for envKey := range values {
						redacted[envKey] = "[redacted]"
					}
					x[key] = redacted
				}
				continue
			}
			redactAppEnv(child)
		}
	}
}

func printAppLogs(raw json.RawMessage) {
	var out struct {
		Logs json.RawMessage `json:"logs"`
	}
	if json.Unmarshal(raw, &out) != nil || len(out.Logs) == 0 || string(out.Logs) == "null" {
		fmt.Println(prettyRawJSON(raw))
		return
	}
	var text string
	if json.Unmarshal(out.Logs, &text) == nil {
		fmt.Print(text)
		if text != "" && !strings.HasSuffix(text, "\n") {
			fmt.Println()
		}
		return
	}
	var lines []string
	if json.Unmarshal(out.Logs, &lines) == nil {
		for _, line := range lines {
			fmt.Println(line)
		}
		return
	}
	fmt.Println(prettyRawJSON(raw))
}
