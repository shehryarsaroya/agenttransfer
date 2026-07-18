package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

func newOpenEnv(t *testing.T) *env {
	t.Helper()
	cfg := Config{DataDir: t.TempDir(), Metrics: "off", OpenSignup: true}
	cfg.ApplyDefaults()
	srv, admin, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.SetBaseURL(ts.URL)
	return &env{t: t, ts: ts, srv: srv, admin: admin, client: ts.Client()}
}

func TestOwnerVerificationClaimsCapOnlyAfterMailboxProof(t *testing.T) {
	e := newEnvCfg(t, Config{MaxAgentsPerOwner: 1})
	first, _, err := e.srv.st.CreateAgent("proof-first", "victim@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := e.srv.st.CreateAgent("proof-second", "victim@example.com", false)
	if err != nil {
		t.Fatalf("second unproven nomination was blocked: %v", err)
	}
	firstToken, _ := e.srv.st.CreateOwnerVerifyToken(first.ID, first.OwnerEmail)
	secondToken, _ := e.srv.st.CreateOwnerVerifyToken(second.ID, second.OwnerEmail)
	resp, _ := e.do("POST", "/verify?t="+firstToken, "", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first mailbox proof: HTTP %d", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/verify?t="+secondToken, "", nil, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second mailbox proof: HTTP %d, want 409", resp.StatusCode)
	}
	if _, err := e.srv.st.PeekVerifyToken(secondToken); err != nil {
		t.Fatalf("cap failure consumed second token: %v", err)
	}
	secondAfter, err := e.srv.st.AgentByID(second.ID)
	if err != nil || secondAfter.OwnerVerified {
		t.Fatalf("second agent verified across cap: %+v err=%v", secondAfter, err)
	}
	if n, err := e.srv.st.CountAgentsByOwner("VICTIM@example.com"); err != nil || n != 1 {
		t.Fatalf("verified owner count=%d err=%v", n, err)
	}
	if _, err := e.srv.st.VerifyOwnerTokenLimited(secondToken, 1); !errors.Is(err, store.ErrOwnerAgentLimit) {
		t.Fatalf("store cap error=%v", err)
	}
}

type signupOut struct {
	AgentID       string `json:"agent_id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	APIKey        string `json:"api_key"`
	Person        string `json:"person"`
	PersonAddress string `json:"person_address"`
	OwnerVerified bool   `json:"owner_verified"`
	Verification  string `json:"verification"`
}

// approve simulates the owner's email click (the instance under test has no
// outbound mail, so the token can't be fetched from an inbox; consume the
// admin verify endpoint instead, which runs the same MarkOwnerVerified +
// person-verification path via the confirm handler's store calls).
func (e *env) approve(agentID string) {
	e.t.Helper()
	if code := e.doJSON("POST", "/v1/agents/"+agentID+"/verify", e.admin, nil, nil); code != 200 {
		e.t.Fatalf("admin verify: %d", code)
	}
}

func TestPersonLifecycle(t *testing.T) {
	e := newOpenEnv(t)

	// 1. First agent births the person: shehryar+laptop, pending.
	var laptop signupOut
	code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "laptop", "as": "shehryar", "owner_email": "owner@example.com"}, &laptop)
	if code != 201 {
		t.Fatalf("person signup: %d", code)
	}
	if laptop.Name != "shehryar+laptop" || !strings.HasPrefix(laptop.Email, "shehryar+laptop@") {
		t.Fatalf("plus name/address wrong: %q %q", laptop.Name, laptop.Email)
	}
	if laptop.Person != "shehryar" || laptop.OwnerVerified {
		t.Fatalf("person=%q verified=%v", laptop.Person, laptop.OwnerVerified)
	}

	sender, senderKey := e.createAgent("sender")
	_ = sender

	// 2. Pending agents are unreachable: direct plus-address and person
	// address both refuse, indistinguishable from nonexistent.
	for _, to := range []string{"shehryar+laptop@local", "shehryar@local"} {
		if code := e.doJSON("POST", "/v1/send", senderKey, map[string]any{"to": []string{to}, "note": "hi"}, nil); code != 400 {
			t.Fatalf("send to %s before approval: %d, want 400", to, code)
		}
	}
	// Person page 404s while pending.
	if resp, _ := e.do("GET", "/@shehryar", "", nil, ""); resp.StatusCode != 404 {
		t.Fatalf("pending person page: %d, want 404", resp.StatusCode)
	}

	// 3. The owner's click approves the agent and verifies the person.
	e.approve(laptop.AgentID)

	// The person's fleet is now addressable both ways.
	for _, to := range []string{"shehryar+laptop@local", "shehryar@local", "shehryar+anything@local"} {
		if code := e.doJSON("POST", "/v1/send", senderKey, map[string]any{"to": []string{to}, "note": "hi " + to}, nil); code != 201 {
			t.Fatalf("send to %s after approval: %d, want 201", to, code)
		}
	}
	var inbox struct {
		Messages []map[string]any `json:"messages"`
	}
	if code := e.doJSON("GET", "/v1/inbox", laptop.APIKey, nil, &inbox); code != 200 {
		t.Fatalf("inbox: %d", code)
	}
	if len(inbox.Messages) != 3 {
		t.Fatalf("laptop should have 3 messages (direct, person, unknown-tag), got %d", len(inbox.Messages))
	}

	// Person page renders with the agent listed (html/template escapes the
	// plus sign as &#43; in text nodes; browsers display it as "+").
	if resp, body := e.do("GET", "/@shehryar", "", nil, ""); resp.StatusCode != 200 ||
		!strings.Contains(string(body), "shehryar&#43;laptop@") {
		t.Fatalf("person page: %d %.120s", resp.StatusCode, body)
	}

	// 4. Second machine joins: pending until its own click; person fan-out
	// excludes it meanwhile.
	var desktop signupOut
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "desktop", "as": "shehryar", "owner_email": "owner@example.com"}, &desktop); code != 201 {
		t.Fatalf("join signup: %d", code)
	}
	if desktop.Name != "shehryar+desktop" || desktop.OwnerVerified {
		t.Fatalf("desktop: %q verified=%v", desktop.Name, desktop.OwnerVerified)
	}
	if code := e.doJSON("POST", "/v1/send", senderKey, map[string]any{"to": []string{"shehryar@local"}, "note": "fanout?"}, nil); code != 201 {
		t.Fatalf("person send: %d", code)
	}
	var desktopInbox struct {
		Messages []map[string]any `json:"messages"`
	}
	_ = e.doJSON("GET", "/v1/inbox", desktop.APIKey, nil, &desktopInbox)
	if len(desktopInbox.Messages) != 0 {
		t.Fatalf("pending desktop must not receive person fan-out, got %d", len(desktopInbox.Messages))
	}
	e.approve(desktop.AgentID)
	if code := e.doJSON("POST", "/v1/send", senderKey, map[string]any{"to": []string{"shehryar@local"}, "note": "both now"}, nil); code != 201 {
		t.Fatalf("person send: %d", code)
	}
	desktopInbox.Messages = nil
	_ = e.doJSON("GET", "/v1/inbox", desktop.APIKey, nil, &desktopInbox)
	if len(desktopInbox.Messages) != 1 {
		t.Fatalf("approved desktop should receive fan-out, got %d", len(desktopInbox.Messages))
	}

	// Fan-out dedup: naming the person AND a member in one send delivers once.
	if code := e.doJSON("POST", "/v1/send", senderKey, map[string]any{
		"to": []string{"shehryar@local", "shehryar+desktop@local"}, "note": "dedup"}, nil); code != 201 {
		t.Fatalf("dedup send: %d", code)
	}
	desktopInbox.Messages = nil
	_ = e.doJSON("GET", "/v1/inbox", desktop.APIKey, nil, &desktopInbox)
	if len(desktopInbox.Messages) != 2 { // "both now" + one "dedup"
		t.Fatalf("dedup: desktop has %d messages, want 2", len(desktopInbox.Messages))
	}
}

func TestPersonNamespaceAndSquatting(t *testing.T) {
	e := newOpenEnv(t)

	// A flat agent's name blocks the same handle...
	e.createAgent("taken")
	var out map[string]any
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "laptop", "as": "taken", "owner_email": "x@example.com"}, &out); code != 400 {
		t.Fatalf("handle over existing agent name: %d, want 400", code)
	}

	// ...and a person's handle blocks the flat agent name (exact-name signups
	// get suffixed instead of colliding, so check the store rule directly).
	var p signupOut
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "laptop", "as": "dana", "owner_email": "dana@example.com"}, &p); code != 201 {
		t.Fatalf("person dana: %d", code)
	}
	if _, _, err := e.srv.st.CreateAgent("dana", "", false); err == nil {
		t.Fatal("flat agent over person handle should fail")
	}

	// Joining someone else's pending handle is refused; a mismatched owner
	// email on a verified handle is refused.
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "evil", "as": "dana"}, &out); code != 403 {
		t.Fatalf("join pending handle: %d, want 403", code)
	}
	e.approve(p.AgentID)
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "ownerless", "as": "dana"}, &out); code != 400 {
		t.Fatalf("join without owner proof: %d, want 400", code)
	}
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "evil", "as": "dana", "owner_email": "mallory@example.com"}, &out); code != 403 {
		t.Fatalf("join with wrong owner: %d, want 403", code)
	}

	// Names with "+" can't be minted directly.
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{"name": "dana+evil"}, &out); code != 400 {
		t.Fatalf("flat plus-name signup: %d, want 400", code)
	}

	// Pubkey lookups on pending agents 404 (no sealing to squatters): make a
	// pending join and check.
	var pend signupOut
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "phone", "as": "dana", "owner_email": "dana@example.com", "pubkey": testRecipient(t)}, &pend); code != 201 {
		t.Fatalf("pending join: %d", code)
	}
	_, key := e.createAgent("prober")
	if code := e.doJSON("GET", "/v1/agents/dana+phone/pubkey", key, nil, &out); code != 404 {
		t.Fatalf("pubkey of pending agent: %d, want 404", code)
	}
	e.approve(pend.AgentID)
	if code := e.doJSON("GET", "/v1/agents/dana+phone/pubkey", key, nil, &out); code != 200 {
		t.Fatalf("pubkey after approval: %d, want 200", code)
	}
}

func TestStalePendingPersonSweep(t *testing.T) {
	e := newOpenEnv(t)
	var p signupOut
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "laptop", "as": "ghost", "owner_email": "g@example.com"}, &p); code != 201 {
		t.Fatalf("signup: %d", code)
	}
	// Fresh pending person is NOT swept.
	if n, err := e.srv.st.SweepStalePendingPersons(3600); err != nil || n != 0 {
		t.Fatalf("fresh sweep: n=%d err=%v", n, err)
	}
	// With ttl 0 (everything is stale) the pending person and its pending
	// agent are released, and the handle is claimable again.
	if n, err := e.srv.st.SweepStalePendingPersons(-1); err != nil || n != 1 {
		t.Fatalf("stale sweep: n=%d err=%v", n, err)
	}
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "laptop", "as": "ghost", "owner_email": "real@example.com"}, &p); code != 201 {
		t.Fatalf("re-claim after sweep: %d", code)
	}
}

func TestInvalidPersonSignupDoesNotReserveHandle(t *testing.T) {
	e := newEnvCfg(t, Config{OpenSignup: true, MaxAgentsPerOwner: 1})
	if code := e.doJSON("POST", "/v1/agents", "", map[string]any{
		"name": "bad+tag", "as": "invalid-cleanup", "owner_email": "other@example.com"}, nil); code != 400 {
		t.Fatalf("invalid tag signup: %d", code)
	}
	var persons int
	if err := e.srv.st.DB.QueryRow(`SELECT COUNT(*) FROM persons WHERE handle='invalid-cleanup'`).Scan(&persons); err != nil {
		t.Fatal(err)
	}
	if persons != 0 {
		t.Fatalf("failed signups reserved %d handles", persons)
	}
}
