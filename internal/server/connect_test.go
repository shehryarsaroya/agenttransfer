package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestConnectEndToEnd runs a connect HOST and a tunneled CLIENT instance in
// one process and walks the whole story: register → tunnel → public download
// through the subdomain → inbound mail via store-and-forward → outbound send
// gating → suspend kill switch.
func TestConnectEndToEnd(t *testing.T) {
	// The mothership. Domain mode is fake (no TLS/SMTP listeners run in
	// tests); ConnectDomain turns on hosting.
	hostCfg := Config{DataDir: t.TempDir(), Metrics: "off", Domain: "hub.test", ConnectDomain: "hub.test"}
	hostCfg.ApplyDefaults()
	host, hostAdmin, err := New(hostCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostTS := httptest.NewServer(host.Handler())
	defer hostTS.Close()
	host.SetBaseURL(hostTS.URL)

	// The laptop instance, borrowing its public face from the host.
	clCfg := Config{DataDir: t.TempDir(), Metrics: "off", Connect: hostTS.URL}
	clCfg.ApplyDefaults()
	laptop, laptopAdmin, err := New(clCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer laptop.Close()
	laptopTS := httptest.NewServer(laptop.Handler())
	defer laptopTS.Close()
	laptop.SetBaseURL(laptopTS.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	laptop.client, err = newConnectClient(laptop)
	if err != nil {
		t.Fatal(err)
	}
	go laptop.client.run(ctx)

	waitFor(t, "tunnel up", func() bool { return laptop.client.connected() })
	name := laptop.client.name
	if !regexp.MustCompile(`^[a-z]+-[a-z]+-\d{2}$`).MatchString(name) {
		t.Fatalf("odd instance name %q", name)
	}
	if got := laptop.Store().Instance(); got != name+".hub.test" {
		t.Fatalf("instance identity not applied: %q", got)
	}

	// Registration must survive a reconnect with the same identity.
	again, err := newConnectClient(laptop)
	if err != nil {
		t.Fatal(err)
	}
	if again.name != name {
		t.Fatalf("registration not resumed: %q vs %q", again.name, name)
	}

	e := &env{t: t, ts: laptopTS, srv: laptop, admin: laptopAdmin, client: laptopTS.Client()}
	agentEmail, agentKey := e.createAgent("bot")
	if agentEmail != "bot@"+name+".hub.test" {
		t.Fatalf("agent address %q not on the borrowed domain", agentEmail)
	}

	// Upload + link on the laptop; download it from the PUBLIC side, through
	// the host, addressed by subdomain.
	payload := []byte("bytes that crossed the tunnel")
	up := e.upload(agentKey, "artifact.bin", payload, "?share=1")
	linkURL := up["link"].(map[string]any)["url"].(string)
	if !strings.HasPrefix(linkURL, "https://"+name+".hub.test/") {
		t.Fatalf("link not minted at the public origin: %s", linkURL)
	}
	path := strings.TrimPrefix(linkURL, "https://"+name+".hub.test")

	req, _ := http.NewRequest("GET", hostTS.URL+path+"?dl=1", nil)
	req.Host = name + ".hub.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, payload) {
		t.Fatalf("tunneled download: HTTP %d, %d bytes", resp.StatusCode, len(body))
	}
	// Egress was metered.
	if used, _ := host.Store().IncrCounterN(name, "connect_bytes", 0); used < int64(len(payload)) {
		t.Fatalf("bandwidth not metered: %d", used)
	}
	// Control paths are not reachable from the public side.
	req, _ = http.NewRequest("GET", hostTS.URL+connectDrainPath, nil)
	req.Host = name + ".hub.test"
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("control path exposed publicly: HTTP %d", resp.StatusCode)
	}

	// Inbound email: queue raw mail on the host (what its SMTP listener does)
	// and watch it arrive in the agent's inbox via drain + ack.
	rawMsg := &mail.Message{
		FromName: "someone", From: "someone@elsewhere.test",
		To: []string{agentEmail}, Subject: "over the wall", Text: "hello from the internet",
		MessageID: "<x1@elsewhere.test>",
	}
	raw, err := rawMsg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.connect.deliverConnectMail(name, []string{agentEmail}, raw); err != nil {
		t.Fatalf("deliverConnectMail refused: %v", err)
	}
	waitFor(t, "queued mail to reach the inbox", func() bool {
		msgs, _ := laptop.Store().ListInbox(agentIDByKey(t, laptop, agentKey), true, "", 0)
		return len(msgs) == 1 && strings.Contains(msgs[0].Text, "hello from the internet")
	})
	waitFor(t, "queue drained on the host", func() bool {
		mails, _ := host.Store().ListConnectMail(name, 0)
		return len(mails) == 0
	})

	// Outbound email: blocked before owner verification, and the block comes
	// from the HOST (proving the control channel round-trips).
	code := e.doJSON("POST", "/v1/send", agentKey,
		map[string]any{"to": []string{"human@example.com"}, "note": "hi"}, nil)
	if code != 502 {
		t.Fatalf("unverified relay send: HTTP %d, want 502", code)
	}
	if err := host.Store().SetConnectVerified(name, "owner@example.com"); err != nil {
		t.Fatal(err)
	}
	// Verified now, but the test host has no relay: the failure must move
	// past the verification gate to the no-relay error.
	var errBody map[string]any
	resp, data := e.do("POST", "/v1/send", agentKey,
		strings.NewReader(`{"to":["human@example.com"],"note":"hi"}`), "application/json")
	_ = json.Unmarshal(data, &errBody)
	if resp.StatusCode != 502 || !strings.Contains(errBody["error"].(string), "no outbound relay") {
		t.Fatalf("verified relay send: HTTP %d %v", resp.StatusCode, errBody)
	}

	// Suspend: tunnel dies, public traffic is refused, and inbound mail is
	// rejected (the kill switch must bite on every path).
	sus := map[string]any{"name": name, "suspended": true}
	hostEnv := &env{t: t, ts: hostTS, srv: host, admin: hostAdmin, client: hostTS.Client()}
	if code := hostEnv.doJSON("POST", "/connect/admin/suspend", hostAdmin, sus, nil); code != 200 {
		t.Fatalf("suspend: HTTP %d", code)
	}
	waitFor(t, "tunnel torn down", func() bool { return !laptop.client.connected() })
	req, _ = http.NewRequest("GET", hostTS.URL+path+"?dl=1", nil)
	req.Host = name + ".hub.test"
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("suspended instance still served: HTTP %d", resp.StatusCode)
	}
	if err := host.connect.deliverConnectMail(name, []string{agentEmail}, raw); err == nil {
		t.Fatal("suspended instance still accepts inbound mail")
	}
}

// A verified instance may only send AS ITSELF: the host must reject a relay
// whose From is a sibling instance or the apex, which would otherwise ride the
// host's DKIM and be auto-trusted at receivers.
func TestConnectRelayFromValidation(t *testing.T) {
	instanceDomain := "amber-fox-42.hub.test"
	raw := func(from string) []byte {
		m := &mail.Message{From: from, To: []string{"x@y.test"}, Subject: "s", Text: "t"}
		b, err := m.Build()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name        string
		envelope    string
		headerFrom  string
		wantAllowed bool
	}{
		{"self", "bot@amber-fox-42.hub.test", "bot@amber-fox-42.hub.test", true},
		{"self angle envelope", "<bot@amber-fox-42.hub.test>", "bot@amber-fox-42.hub.test", true},
		{"sibling instance", "bot@evil-owl-99.hub.test", "bot@evil-owl-99.hub.test", false},
		{"apex", "admin@hub.test", "admin@hub.test", false},
		{"header spoof, envelope ok", "bot@amber-fox-42.hub.test", "ceo@victim.com", false},
		{"envelope spoof, header ok", "bot@victim.com", "bot@amber-fox-42.hub.test", false},
	}
	for _, c := range cases {
		got := senderIsInstance(c.envelope, raw(c.headerFrom), instanceDomain)
		if got != c.wantAllowed {
			t.Errorf("%s: senderIsInstance = %v, want %v", c.name, got, c.wantAllowed)
		}
	}
}

func agentIDByKey(t *testing.T, s *Server, key string) string {
	t.Helper()
	a, err := s.Store().AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

func TestConnectSubdomainParsing(t *testing.T) {
	s := &Server{cfg: Config{ConnectDomain: "hub.test"}}
	h := newConnectHost(s)
	cases := []struct {
		host string
		name string
		ok   bool
	}{
		{"amber-fox-42.hub.test", "amber-fox-42", true},
		{"amber-fox-42.hub.test:443", "amber-fox-42", true},
		{"AMBER-FOX-42.HUB.TEST", "amber-fox-42", true},
		{"hub.test", "", false},     // apex is not an instance
		{"a.b.hub.test", "", false}, // one label only
		{"amber-fox-42.other.test", "", false},
		{".hub.test", "", false},
	}
	for _, c := range cases {
		name, ok := h.isConnectSubdomain(c.host)
		if ok != c.ok || name != c.name {
			t.Errorf("isConnectSubdomain(%q) = %q,%v want %q,%v", c.host, name, ok, c.name, c.ok)
		}
	}
}

func TestConnectMailQueueCaps(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), Metrics: "off"}
	cfg.ApplyDefaults()
	srv, _, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	st := srv.Store()
	if _, err := st.CreateConnectInstance("misty-owl-11"); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat([]byte("m"), 100)
	for i := 0; i < 3; i++ {
		if err := st.EnqueueConnectMail("misty-owl-11", []string{"a@x"}, raw, 3, 1<<20); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := st.EnqueueConnectMail("misty-owl-11", []string{"a@x"}, raw, 3, 1<<20); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("count cap not enforced: %v", err)
	}
	if err := st.EnqueueConnectMail("misty-owl-11", []string{"a@x"}, raw, 100, 350); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("byte cap not enforced: %v", err)
	}
}

func TestConnectReap(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), Metrics: "off"}
	cfg.ApplyDefaults()
	srv, _, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	st := srv.Store()

	if _, err := st.CreateConnectInstance("pale-newt-77"); err != nil { // never connects
		t.Fatal(err)
	}
	if _, err := st.CreateConnectInstance("bold-crow-88"); err != nil { // connected recently
		t.Fatal(err)
	}
	if err := st.TouchConnectInstance("bold-crow-88"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE connect_instances SET created_at=1 WHERE name='pale-newt-77'`); err != nil {
		t.Fatal(err)
	}
	reaped, err := st.ReapConnectInstances(connectGraceNew, connectGraceIdle)
	if err != nil {
		t.Fatal(err)
	}
	if len(reaped) != 1 || reaped[0] != "pale-newt-77" {
		t.Fatalf("reaped %v, want just the never-connected one", reaped)
	}
	if _, err := st.ConnectInstanceByName("bold-crow-88"); err != nil {
		t.Fatal("live instance was reaped")
	}
}

func TestConnectHeartbeatProtectsLiveTunnelFromIdleReap(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", Domain: "hub.test", ConnectDomain: "hub.test"}
	cfg.ApplyDefaults()
	srv, _, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := srv.st.CreateConnectInstance("steady-otter-42"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.st.DB.Exec(`UPDATE connect_instances SET created_at=1,last_seen=1
		WHERE name='steady-otter-42'`); err != nil {
		t.Fatal(err)
	}
	srv.connect.mu.Lock()
	srv.connect.sessions["steady-otter-42"] = &connectSession{name: "steady-otter-42"}
	srv.connect.mu.Unlock()
	srv.connect.heartbeatLiveInstances()
	reaped, err := srv.st.ReapConnectInstances(time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(reaped) != 0 {
		t.Fatalf("live heartbeat registration was reaped: %v", reaped)
	}
}

func TestConnectClientRegistersAgainAfterHostReapsRegistration(t *testing.T) {
	hostCfg := Config{DataDir: t.TempDir(), Metrics: "off", Domain: "hub.test", ConnectDomain: "hub.test"}
	hostCfg.ApplyDefaults()
	host, _, err := New(hostCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostTS := httptest.NewServer(host.Handler())
	defer hostTS.Close()
	host.SetBaseURL(hostTS.URL)

	clientCfg := Config{DataDir: t.TempDir(), Metrics: "off", Connect: hostTS.URL}
	clientCfg.ApplyDefaults()
	client, _, err := New(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.client, err = newConnectClient(client)
	if err != nil {
		t.Fatal(err)
	}
	go client.client.run(ctx)
	waitFor(t, "initial tunnel", client.client.connected)
	oldName := client.client.name

	if _, err := host.st.DB.Exec(`DELETE FROM connect_instances WHERE name=?`, oldName); err != nil {
		t.Fatal(err)
	}
	host.connect.mu.Lock()
	if cs := host.connect.sessions[oldName]; cs != nil && cs.sess != nil {
		_ = cs.sess.Close()
	}
	host.connect.mu.Unlock()
	waitFor(t, "fresh registration after host reap", func() bool {
		return client.client.connected() && client.client.name != "" && client.client.name != oldName
	})
	if _, err := host.st.ConnectInstanceByName(client.client.name); err != nil {
		t.Fatalf("new registration %q missing on host: %v", client.client.name, err)
	}
	if got, _ := client.st.GetSetting("connect_name"); got != client.client.name {
		t.Fatalf("persisted registration=%q, live=%q", got, client.client.name)
	}
}

func TestConnectClientDoesNotTunnelUntilBorrowedIdentityIsApplied(t *testing.T) {
	hostCfg := Config{DataDir: t.TempDir(), Metrics: "off", Domain: "hub.test", ConnectDomain: "hub.test"}
	hostCfg.ApplyDefaults()
	host, _, err := New(hostCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostTS := httptest.NewServer(host.Handler())
	defer hostTS.Close()
	host.SetBaseURL(hostTS.URL)

	clientCfg := Config{DataDir: t.TempDir(), Metrics: "off", Connect: hostTS.URL}
	clientCfg.ApplyDefaults()
	client, _, err := New(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	agent, _, err := client.st.CreateAgent("before-connect", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.st.DB.Exec(`CREATE TRIGGER reject_connect_identity
		BEFORE UPDATE OF email ON agents
		BEGIN SELECT RAISE(ABORT,'forced identity failure'); END`); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.client, err = newConnectClient(client)
	if err != nil {
		t.Fatal(err)
	}
	go client.client.run(ctx)
	waitFor(t, "connect registration", client.client.registered)
	// Give the run loop enough time to attempt the rejected local transition.
	time.Sleep(100 * time.Millisecond)
	if client.client.connected() {
		t.Fatal("tunnel opened before the borrowed identity was applied")
	}
	unchanged, err := client.st.AgentByID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Email != "before-connect@local" || client.st.Instance() != "local" {
		t.Fatalf("failed identity transition changed local state: agent=%q instance=%q", unchanged.Email, client.st.Instance())
	}

	if _, err := client.st.DB.Exec(`DROP TRIGGER reject_connect_identity`); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel after identity recovery", client.client.connected)
	name, _, _ := client.client.identity()
	updated, err := client.st.AgentByID(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantDomain := name + ".hub.test"
	if client.st.Instance() != wantDomain || updated.Email != "before-connect@"+wantDomain {
		t.Fatalf("recovered identity: agent=%q instance=%q want domain %q", updated.Email, client.st.Instance(), wantDomain)
	}
}

func TestNewConnectClientPropagatesSavedIdentityFailure(t *testing.T) {
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", Connect: "https://hub.test"}
	cfg.ApplyDefaults()
	srv, _, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, _, err := srv.st.CreateAgent("saved-connect", "", false); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"connect_url":        cfg.Connect,
		"connect_name":       "saved-otter-42",
		"connect_token":      "at_conn_saved",
		"connect_public_url": "https://saved-otter-42.hub.test",
	} {
		if err := srv.st.SetSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.st.DB.Exec(`CREATE TRIGGER reject_saved_connect_identity
		BEFORE UPDATE OF email ON agents
		BEGIN SELECT RAISE(ABORT,'forced saved identity failure'); END`); err != nil {
		t.Fatal(err)
	}
	if client, err := newConnectClient(srv); err == nil || client != nil || !strings.Contains(err.Error(), "rename instance") {
		t.Fatalf("newConnectClient = (%v, %v), want propagated rename failure", client, err)
	}
	if srv.st.Instance() != "local" {
		t.Fatalf("failed saved identity changed instance to %q", srv.st.Instance())
	}
}

func TestConnectForwardedRemoteAddrFormatsIPv6(t *testing.T) {
	for _, tt := range []struct {
		xff  string
		want string
		ok   bool
	}{
		{xff: "198.51.100.7", want: "198.51.100.7:0", ok: true},
		{xff: "192.0.2.1, 2001:db8::7", want: "[2001:db8::7]:0", ok: true},
		{xff: "not-an-ip:1234", ok: false},
		{xff: "", ok: false},
	} {
		got, ok := connectForwardedRemoteAddr(tt.xff)
		if got != tt.want || ok != tt.ok {
			t.Errorf("connectForwardedRemoteAddr(%q)=(%q,%v), want (%q,%v)", tt.xff, got, ok, tt.want, tt.ok)
		}
	}
}
