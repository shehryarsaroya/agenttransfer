package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/s3/s3test"
)

// relaunchEnv is a hosted-shaped instance: accounts + OAuth on, blobs in a
// fake S3 bucket, public links only for verified folders.
func relaunchEnv(t *testing.T) (*env, *s3test.Fake) {
	t.Helper()
	fake := s3test.New()
	bucket := httptest.NewServer(fake)
	t.Cleanup(bucket.Close)
	e := newEnvCfg(t, Config{
		Accounts: true, DevLoginLinks: true, PublicLinks: "verified", OpenSignup: true,
		S3Endpoint: bucket.URL, S3Bucket: "blobs", S3AccessKey: "AK", S3SecretKey: "SK",
	})
	e.srv.allowPrivateWebhooks = true // the fake bucket and file servers are loopback
	return e, fake
}

// browser is a cookie-carrying client that does not follow redirects.
type browser struct {
	t    *testing.T
	e    *env
	http *http.Client
}

func newBrowser(e *env) *browser {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &browser{t: e.t, e: e, http: c}
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.e.ts.URL + path
	}
	resp, err := b.http.Get(u)
	if err != nil {
		b.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (b *browser) post(path string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	resp, err := b.http.PostForm(b.e.ts.URL+path, form)
	if err != nil {
		b.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

var (
	devLinkRe = regexp.MustCompile(`/login/verify\?t=([A-Za-z0-9_\-%]+)`)
	csrfRe    = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
)

// signIn completes the email-link flow and returns the CSRF token.
func (b *browser) signIn(email, next string) {
	b.t.Helper()
	_, page := b.post("/login", url.Values{"email": {email}, "next": {next}})
	m := devLinkRe.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("no dev sign-in link in page: %s", page)
	}
	tok, _ := url.QueryUnescape(m[1])
	resp, _ := b.post("/login/verify", url.Values{"t": {tok}})
	if resp.StatusCode != http.StatusSeeOther {
		b.t.Fatalf("verify: HTTP %d", resp.StatusCode)
	}
}

func pkce() (verifier, challenge string) {
	buf := make([]byte, 32)
	rand.Read(buf)
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// connect runs register → authorize → consent → token like an MCP client,
// returning the token response.
func connect(t *testing.T, e *env, b *browser, clientName, redirect, tag string) map[string]any {
	t.Helper()
	var reg map[string]any
	if code := e.doJSON("POST", "/oauth/register", "", map[string]any{
		"client_name": clientName, "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none",
	}, &reg); code != http.StatusCreated {
		t.Fatalf("register: HTTP %d", code)
	}
	clientID := reg["client_id"].(string)
	verifier, challenge := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st8"},
		"scope": {"files"}, "resource": {e.ts.URL + "/mcp"}}
	resp, page := b.get("/oauth/authorize?" + q.Encode())
	var loc *url.URL
	if resp.StatusCode == http.StatusFound {
		loc, _ = url.Parse(resp.Header.Get("Location")) // remembered consent
	} else {
		m := csrfRe.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no consent form (HTTP %d): %s", resp.StatusCode, page)
		}
		form := url.Values{}
		for k, v := range q {
			form[k] = v
		}
		form.Set("csrf", m[1])
		form.Set("decision", "allow")
		form.Set("tag", tag)
		resp, page = b.post("/oauth/authorize", form)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("consent: HTTP %d %s", resp.StatusCode, page)
		}
		loc, _ = url.Parse(resp.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "st8" || loc.Query().Get("iss") != e.ts.URL || loc.Query().Get("code") == "" {
		t.Fatalf("bad redirect %s", loc)
	}
	tokResp, err := http.PostForm(e.ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {e.ts.URL + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	var out map[string]any
	json.NewDecoder(tokResp.Body).Decode(&out)
	if tokResp.StatusCode != 200 || out["access_token"] == nil {
		t.Fatalf("token: HTTP %d %v", tokResp.StatusCode, out)
	}
	out["client_id"] = clientID
	out["code"] = loc.Query().Get("code")
	out["verifier"] = verifier
	return out
}

func mcpCallTool(t *testing.T, e *env, token, name string, args any) (map[string]any, bool) {
	t.Helper()
	res := hostedMCPRPC(t, e, token, "tools/call", map[string]any{"name": name, "arguments": args})
	isErr, _ := res["isError"].(bool)
	sc, _ := res["structuredContent"].(map[string]any)
	if sc == nil {
		sc = map[string]any{}
		if content, _ := res["content"].([]any); len(content) > 0 {
			sc["text"] = content[0].(map[string]any)["text"]
		}
	}
	return sc, isErr
}

func TestOAuthConnectorsShareOneDrive(t *testing.T) {
	e, _ := relaunchEnv(t)

	// Unauthenticated MCP gets the RFC 9728 challenge clients start OAuth from.
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}})
	resp, _ := e.do("POST", "/mcp", "", bytes.NewReader(body), "application/json")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("challenge: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	var prm, asm map[string]any
	e.doJSON("GET", "/.well-known/oauth-protected-resource/mcp", "", nil, &prm)
	e.doJSON("GET", "/.well-known/oauth-authorization-server", "", nil, &asm)
	if prm["resource"] != e.ts.URL+"/mcp" || asm["issuer"] != e.ts.URL || asm["client_id_metadata_document_supported"] != true {
		t.Fatalf("metadata: %v %v", prm, asm)
	}

	b := newBrowser(e)
	b.signIn("Dana@Example.com", "/account")
	claude := connect(t, e, b, "Claude", "https://claude.ai/api/mcp/auth_callback", "claude")
	ctok := claude["access_token"].(string)

	tools := hostedMCPRPC(t, e, ctok, "tools/list", map[string]any{})
	var save map[string]any
	for _, raw := range tools["tools"].([]any) {
		tool := raw.(map[string]any)
		if tool["name"] == "save_file" {
			save = tool
		}
		ann, _ := tool["annotations"].(map[string]any)
		if tool["title"] == nil || ann["readOnlyHint"] == nil || ann["destructiveHint"] == nil {
			t.Fatalf("tool %v lacks title/annotations", tool["name"])
		}
	}
	if save == nil || save["_meta"].(map[string]any)["openai/fileParams"] == nil || save["securitySchemes"] == nil {
		t.Fatalf("save_file descriptor: %v", save)
	}

	out, isErr := mcpCallTool(t, e, ctok, "save_file", map[string]any{"name": "plan.md", "content": "# launch plan\nship it"})
	if isErr || out["saved"] != "plan.md" {
		t.Fatalf("save_file: %v", out)
	}
	who, _ := mcpCallTool(t, e, ctok, "whoami", map[string]any{})
	if who["email"] != "dana+claude@"+e.srv.st.Instance() {
		t.Fatalf("claude acts as %v", who["email"])
	}

	// A second app (ChatGPT) sees the same file and can read it.
	chat := connect(t, e, b, "ChatGPT", "https://chatgpt.com/connector_platform_oauth_redirect", "chatgpt")
	gtok := chat["access_token"].(string)
	list, _ := mcpCallTool(t, e, gtok, "list_files", map[string]any{"query": "plan"})
	if list["count"] != float64(1) {
		t.Fatalf("chatgpt list: %v", list)
	}
	read, isErr := mcpCallTool(t, e, gtok, "read_file", map[string]any{"file": "plan.md"})
	if isErr || !strings.Contains(fmt.Sprint(read["content"]), "ship it") {
		t.Fatalf("read_file: %v", read)
	}
	link, isErr := mcpCallTool(t, e, gtok, "get_link", map[string]any{"file": "plan.md", "ttl": "1h"})
	if isErr || link["url"] == nil {
		t.Fatalf("get_link: %v", link)
	}
	// Verified person: the link downloads anonymously (redirect to the bucket).
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lr, err := noRedirect.Get(link["url"].(string) + "?dl=1")
	if err != nil || lr.StatusCode != http.StatusFound {
		t.Fatalf("link download: %v %v", lr, err)
	}
	obj, err := http.Get(lr.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if string(got) != "# launch plan\nship it" {
		t.Fatalf("bucket bytes = %q", got)
	}

	// Remembered consent: reconnecting the same client skips the form.
	_ = connect(t, e, b, "ChatGPT", "https://chatgpt.com/connector_platform_oauth_redirect", "chatgpt")

	// Refresh rotates; replaying the old refresh token kills the family.
	rr, _ := http.PostForm(e.ts.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {claude["refresh_token"].(string)}, "client_id": {claude["client_id"].(string)}})
	var rot map[string]any
	json.NewDecoder(rr.Body).Decode(&rot)
	rr.Body.Close()
	if rr.StatusCode != 200 || rot["refresh_token"] == claude["refresh_token"] {
		t.Fatalf("refresh: %d %v", rr.StatusCode, rot)
	}
	replay, _ := http.PostForm(e.ts.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {claude["refresh_token"].(string)}})
	replay.Body.Close()
	if replay.StatusCode != 400 {
		t.Fatalf("refresh replay accepted: %d", replay.StatusCode)
	}
	resp, _ = e.do("POST", "/mcp", rot["access_token"].(string), bytes.NewReader(body), "application/json")
	if resp.StatusCode != 401 {
		t.Fatalf("rotated family survived replay: %d", resp.StatusCode)
	}
	// The authorization code is single-use.
	again, _ := http.PostForm(e.ts.URL+"/oauth/token", url.Values{"grant_type": {"authorization_code"},
		"code": {chat["code"].(string)}, "code_verifier": {chat["verifier"].(string)}})
	again.Body.Close()
	if again.StatusCode != 400 {
		t.Fatalf("code reuse accepted: %d", again.StatusCode)
	}
}

func TestOAuthRejectsBadPKCEAndRedirects(t *testing.T) {
	e, _ := relaunchEnv(t)
	var reg map[string]any
	e.doJSON("POST", "/oauth/register", "", map[string]any{"client_name": "x", "redirect_uris": []string{"http://127.0.0.1/cb"}}, &reg)
	if code := e.doJSON("POST", "/oauth/register", "", map[string]any{"redirect_uris": []string{"http://evil.example/cb"}}, nil); code != 400 {
		t.Fatalf("non-loopback http redirect registered: %d", code)
	}
	b := newBrowser(e)
	b.signIn("p@example.com", "/account")
	_, challenge := pkce()
	// An unregistered redirect never receives a redirect (error page instead).
	q := url.Values{"response_type": {"code"}, "client_id": {reg["client_id"].(string)}, "redirect_uri": {"https://attacker.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	resp, _ := b.get("/oauth/authorize?" + q.Encode())
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("redirected to an unregistered URI: %s", resp.Header.Get("Location"))
	}
	// Loopback redirects match on any port.
	q.Set("redirect_uri", "http://127.0.0.1:53682/cb")
	resp, page := b.get("/oauth/authorize?" + q.Encode())
	if resp.StatusCode != 200 || !strings.Contains(page, "Allow") {
		t.Fatalf("loopback port not accepted: %d", resp.StatusCode)
	}
	// Missing PKCE is reported back by redirect.
	q.Del("code_challenge")
	resp, _ = b.get("/oauth/authorize?" + q.Encode())
	if loc, _ := url.Parse(resp.Header.Get("Location")); resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("missing PKCE: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestDirectUploadsSingleMultipartAndMismatch(t *testing.T) {
	e, fake := relaunchEnv(t)
	oldSingle, oldPart := singlePutMax, minPartSize
	singlePutMax, minPartSize = 1<<10, 5<<10 // tiny thresholds: exercise multipart
	t.Cleanup(func() { singlePutMax, minPartSize = oldSingle, oldPart })
	_, key := e.createAgent("uploader")

	// Single PUT.
	small := []byte("small but mighty")
	var sess map[string]any
	if code := e.doJSON("POST", "/v1/uploads", key, map[string]any{"name": "s.txt", "size": len(small)}, &sess); code != 201 {
		t.Fatalf("create upload: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPut, sess["put_url"].(string), bytes.NewReader(small))
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("put: %v %v", r, err)
	}
	var done map[string]any
	if code := e.doJSON("POST", "/v1/uploads/"+sess["upload_id"].(string)+"/complete", key, nil, &done); code != 201 {
		t.Fatalf("complete: %d", code)
	}
	if done["file"].(map[string]any)["sha256"] != hexOf(small) {
		t.Fatalf("complete result %v", done)
	}

	// Multipart: 3 parts of 5 KiB + tail, uploaded via presigned part URLs,
	// completed without ETags (server lists parts).
	big := make([]byte, 17<<10)
	rand.Read(big)
	var mp map[string]any
	e.doJSON("POST", "/v1/uploads", key, map[string]any{"name": "big.bin", "size": len(big), "sha256": hexOf(big)}, &mp)
	if mp["mode"] != "multipart" || mp["parts"] != float64(4) {
		t.Fatalf("multipart session: %v", mp)
	}
	ps := int(mp["part_size"].(float64))
	for _, raw := range mp["part_urls"].([]any) {
		p := raw.(map[string]any)
		n := int(p["part_number"].(float64))
		end := min(n*ps, len(big))
		req, _ := http.NewRequest(http.MethodPut, p["url"].(string), bytes.NewReader(big[(n-1)*ps:end]))
		if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
			t.Fatalf("part %d: %v %v", n, r, err)
		}
	}
	if code := e.doJSON("POST", "/v1/uploads/"+mp["upload_id"].(string)+"/complete", key, nil, &done); code != 201 {
		t.Fatalf("multipart complete: %d", code)
	}
	// Download redirects to the bucket and the bytes match.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	dreq, _ := http.NewRequest("GET", e.ts.URL+"/v1/files/"+hexOf(big)+"/content", nil)
	dreq.Header.Set("Authorization", "Bearer "+key)
	dr, _ := noRedirect.Do(dreq)
	if dr.StatusCode != http.StatusFound || dr.Header.Get("X-Sha256") != hexOf(big) {
		t.Fatalf("download: %d %v", dr.StatusCode, dr.Header)
	}
	obj, _ := http.Get(dr.Header.Get("Location"))
	got, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if !bytes.Equal(got, big) {
		t.Fatal("multipart bytes mismatch")
	}

	// Declared hash mismatch: rejected and nothing is filed.
	var bad map[string]any
	e.doJSON("POST", "/v1/uploads", key, map[string]any{"name": "lie.txt", "size": 5, "sha256": hexOf([]byte("truth"))}, &bad)
	req, _ = http.NewRequest(http.MethodPut, bad["put_url"].(string), strings.NewReader("lies!"))
	http.DefaultClient.Do(req)
	if code := e.doJSON("POST", "/v1/uploads/"+bad["upload_id"].(string)+"/complete", key, nil, nil); code != 400 {
		t.Fatalf("mismatched upload accepted: %d", code)
	}
	var files map[string]any
	e.doJSON("GET", "/v1/files", key, nil, &files)
	for _, f := range files["files"].([]any) {
		if f.(map[string]any)["name"] == "lie.txt" {
			t.Fatal("mismatched upload was filed")
		}
	}
	// Re-declaring content already in the folder is an instant upload.
	var inst map[string]any
	e.doJSON("POST", "/v1/uploads", key, map[string]any{"name": "copy.bin", "size": len(big), "sha256": hexOf(big)}, &inst)
	if inst["deduplicated"] != true {
		t.Fatalf("instant upload: %v", inst)
	}
	_ = fake
}

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestUnverifiedLinksNeedAnAgentCredential(t *testing.T) {
	e, _ := relaunchEnv(t)
	// Open signup (no admin): a keyed agent with no verified owner.
	var signup map[string]any
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "anon-agent"}, &signup); code != 201 {
		t.Fatalf("open signup: %d", code)
	}
	anon := signup["api_key"].(string)
	_, other := e.createAgent("other-agent")
	up := e.upload(anon, "payload.bin", []byte("not for the public"), "?share=1")
	link := up["link"].(map[string]any)["url"].(string)
	resp, _ := e.do("GET", strings.TrimPrefix(link, e.ts.URL)+"?dl=1", "", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous download of an unverified link: %d", resp.StatusCode)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", link+"?dl=1", nil)
	req.Header.Set("Authorization", "Bearer "+other)
	r, err := noRedirect.Do(req)
	if err != nil || r.StatusCode != http.StatusFound {
		t.Fatalf("agent download: %v %v", r, err)
	}
}

func TestSaveFileFromChatGPTFileParam(t *testing.T) {
	e, _ := relaunchEnv(t)
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		io.WriteString(w, "a,b\n1,2\n")
	}))
	defer files.Close()
	_, key := e.createAgent("attach-agent")
	out, isErr := mcpCallTool(t, e, key, "save_file", map[string]any{"file": map[string]any{
		"download_url": files.URL + "/f.csv", "file_id": "file_123", "file_name": "numbers.csv", "mime_type": "text/csv"}})
	if isErr || out["saved"] != "numbers.csv" || out["size"] != float64(8) {
		t.Fatalf("save from fileParams: %v", out)
	}
	// A non-https URL is refused when SSRF protection is on.
	e.srv.allowPrivateWebhooks = false
	_, isErr = mcpCallTool(t, e, key, "save_file", map[string]any{"file": map[string]any{"download_url": files.URL, "file_id": "f"}})
	if !isErr {
		t.Fatal("plain-http loopback fetch allowed")
	}
}

func TestAccountPageDriveAndKeys(t *testing.T) {
	e, _ := relaunchEnv(t)
	b := newBrowser(e)
	b.signIn("owner@example.com", "/account")
	resp, page := b.get("/account")
	if resp.StatusCode != 200 || !strings.Contains(page, "owner@") {
		t.Fatalf("account page: %d", resp.StatusCode)
	}
	csrf := csrfRe.FindStringSubmatch(page)[1]
	// Create an API key for Muse; it shares the drive.
	_, page = b.post("/account/agents", url.Values{"csrf": {csrf}, "tag": {"muse"}})
	key := regexp.MustCompile(`at_live_[A-Za-z0-9_\-]+`).FindString(page)
	if key == "" {
		t.Fatal("no API key shown")
	}
	e.upload(key, "from-muse.txt", []byte("hello from muse"), "")
	// The browser's drive API (cookie + CSRF header) sees it.
	req, _ := http.NewRequest("GET", e.ts.URL+"/account/api/files", nil)
	r, _ := b.http.Do(req)
	var list map[string]any
	json.NewDecoder(r.Body).Decode(&list)
	r.Body.Close()
	if len(list["files"].([]any)) != 1 {
		t.Fatalf("drive via web API: %v", list)
	}
	// State-changing web API calls need the CSRF header.
	del, _ := http.NewRequest("DELETE", e.ts.URL+"/account/api/files/"+hexOf([]byte("hello from muse")), nil)
	r, _ = b.http.Do(del)
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without CSRF: %d", r.StatusCode)
	}
	del.Header.Set("X-CSRF-Token", csrf)
	r, _ = b.http.Do(del)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("delete with CSRF: %d", r.StatusCode)
	}
	// Password sign-in for reviewer accounts.
	b.post("/account/password", url.Values{"csrf": {csrf}, "password": {"reviewer-password-1"}})
	b2 := newBrowser(e)
	resp, _ = b2.post("/login", url.Values{"email": {"owner@example.com"}, "password": {"reviewer-password-1"}, "next": {"/account"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("password sign-in: %d", resp.StatusCode)
	}
	resp, _ = newBrowser(e).post("/login", url.Values{"email": {"owner@example.com"}, "password": {"wrong-password!!"}})
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("wrong password signed in")
	}
}
