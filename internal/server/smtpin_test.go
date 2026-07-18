package server

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	gosmtp "github.com/emersion/go-smtp"

	mailpkg "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// A valid DKIM signature only makes an offer trusted when its signing domain
// aligns with the From domain — a signature from an unrelated domain on a
// spoofed From must stay "fail".
func TestDKIMVerdictRequiresAlignment(t *testing.T) {
	pass := func(d string) *dkim.Verification { return &dkim.Verification{Domain: d} }
	fail := func(d string) *dkim.Verification { return &dkim.Verification{Domain: d, Err: errors.New("bad sig")} }

	cases := []struct {
		name   string
		verifs []*dkim.Verification
		from   string
		want   string
	}{
		{"exact match", []*dkim.Verification{pass("example.com")}, "example.com", "pass"},
		{"parent is not exact", []*dkim.Verification{pass("example.com")}, "agents.example.com", "fail"},
		{"subdomain is not exact", []*dkim.Verification{pass("mail.example.com")}, "example.com", "fail"},
		{"shared public suffix tenant cannot align", []*dkim.Verification{pass("attacker.github.io")}, "github.io", "fail"},
		{"case-insensitive", []*dkim.Verification{pass("Example.COM")}, "example.com", "pass"},
		{"unrelated domain (spoof)", []*dkim.Verification{pass("attacker.com")}, "victim.com", "fail"},
		{"suffix but not label boundary", []*dkim.Verification{pass("notexample.com")}, "example.com", "fail"},
		{"invalid signature, aligned domain", []*dkim.Verification{fail("example.com")}, "example.com", "fail"},
		{"one bad one good", []*dkim.Verification{fail("example.com"), pass("example.com")}, "example.com", "pass"},
		{"good but unaligned plus bad aligned", []*dkim.Verification{pass("attacker.com"), fail("example.com")}, "example.com", "fail"},
		{"empty from domain", []*dkim.Verification{pass("example.com")}, "", "fail"},
	}
	for _, tc := range cases {
		if got := dkimVerdict(tc.verifs, tc.from); got != tc.want {
			t.Errorf("%s: dkimVerdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSMTPMailboxCapReturnsRetryable452(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-full")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := e.srv.st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO messages(id,agent_id,from_addr,received_at) VALUES(?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.MaxInboxMessagesPerAgent; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("full-%05d", i), agent.ID, "seed@example.test", i+1); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	raw := "From: sender@example.test\r\nTo: " + agent.Email + "\r\n" +
		"Subject: over cap\r\nMessage-ID: <full-cap@example.test>\r\n\r\nhello\r\n"
	ss := &smtpSession{s: e.srv, from: "sender@example.test", agents: []store.Agent{agent}}
	err = ss.Data(strings.NewReader(raw))
	var smtpErr *gosmtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 452 || smtpErr.EnhancedCode != (gosmtp.EnhancedCode{4, 2, 2}) {
		t.Fatalf("full mailbox Data error=%v, want 452 4.2.2", err)
	}
}

func TestConcurrentInboundMessageIDIsIdempotentWithAttachments(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-idempotent")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	in := &mailpkg.Inbound{
		From: "sender@example.test", To: []string{agent.Email}, Subject: "one",
		Text: "hello", MessageID: "<same-message@example.test>",
		Attachments: []mailpkg.InAttachment{{Name: "one.txt", MIME: "text/plain", Data: []byte("attachment")}},
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- e.srv.ingestInbound(agent, in.From, in, "pass")
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	messages, err := e.srv.st.ListInbox(agent.ID, false, "", 20)
	if err != nil || len(messages) != 1 {
		t.Fatalf("messages=%+v err=%v", messages, err)
	}
	files, err := e.srv.st.ListFiles(agent.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%+v err=%v", files, err)
	}
}

func TestHeaderlessInboundRetryGetsStableIdentity(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-headerless")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nTo: " + agent.Email + "\r\nSubject: retry me\r\n\r\nhello\r\n")
	for i := 0; i < 2; i++ {
		in, err := mailpkg.ParseInbound(bytes.NewReader(raw), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		ensureInboundMessageID(in, raw)
		if in.MessageID == "" {
			t.Fatal("header-less message did not receive a fallback id")
		}
		if err := e.srv.ingestInbound(agent, in.From, in, "none"); err != nil {
			t.Fatal(err)
		}
	}
	messages, err := e.srv.st.ListInbox(agent.ID, false, "", 20)
	if err != nil || len(messages) != 1 {
		t.Fatalf("header-less retry created duplicates: messages=%+v err=%v", messages, err)
	}
}

func TestInboundMessageFailureRollsBackNewAttachmentEntries(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-rollback")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.st.DB.Exec(`CREATE TRIGGER reject_test_message BEFORE INSERT ON messages
		BEGIN SELECT RAISE(FAIL, 'forced message failure'); END`); err != nil {
		t.Fatal(err)
	}
	in := &mailpkg.Inbound{
		From: "sender@example.test", To: []string{agent.Email}, MessageID: "<rollback@example.test>",
		Attachments: []mailpkg.InAttachment{{Name: "partial.bin", MIME: "application/octet-stream", Data: []byte("partial")}},
	}
	if err := e.srv.ingestInbound(agent, in.From, in, "pass"); err == nil {
		t.Fatal("forced message failure was ignored")
	}
	files, err := e.srv.st.ListFiles(agent.ID)
	if err != nil || len(files) != 0 {
		t.Fatalf("partial attachment entries survived: %+v err=%v", files, err)
	}
}

func TestRepeatedInboundAttachmentRefreshesArrivalTTL(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-repeat-attachment")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	attachment := mailpkg.InAttachment{Name: "repeat.txt", MIME: "text/plain", Data: []byte("same")}
	first := &mailpkg.Inbound{From: "sender@example.test", To: []string{agent.Email}, MessageID: "<repeat-1@example.test>", Attachments: []mailpkg.InAttachment{attachment}}
	if err := e.srv.ingestInbound(agent, first.From, first, "pass"); err != nil {
		t.Fatal(err)
	}
	files, err := e.srv.st.ListFiles(agent.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("first attachment: %+v err=%v", files, err)
	}
	nearExpiry := time.Now().Unix() + 1
	if _, err := e.srv.st.DB.Exec(`UPDATE files SET expires_at=? WHERE id=?`, nearExpiry, files[0].ID); err != nil {
		t.Fatal(err)
	}
	second := &mailpkg.Inbound{From: first.From, To: first.To, MessageID: "<repeat-2@example.test>", Attachments: []mailpkg.InAttachment{attachment}}
	if err := e.srv.ingestInbound(agent, second.From, second, "pass"); err != nil {
		t.Fatal(err)
	}
	files, err = e.srv.st.ListFiles(agent.ID)
	if err != nil || len(files) != 1 || files[0].ExpiresAt < time.Now().Add(e.srv.cfg.DefaultTTL-time.Minute).Unix() {
		t.Fatalf("repeated attachment TTL was not refreshed: %+v err=%v", files, err)
	}
}

func TestInboundDuplicateCannotExpireClaimedPersistentFile(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("smtp-kept-attachment")
	agent, err := e.srv.st.AgentByKey(key)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("already kept")
	sha, size, err := e.srv.st.PutBlob(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.st.AddFile(agent.ID, sha, "kept.txt", "text/plain", size, "upload", true, 0); err != nil {
		t.Fatal(err)
	}
	in := &mailpkg.Inbound{
		From: "sender@example.test", To: []string{agent.Email}, MessageID: "<kept-duplicate@example.test>",
		Attachments: []mailpkg.InAttachment{{Name: "kept.txt", MIME: "text/plain", Data: payload}},
	}
	if err := e.srv.ingestInbound(agent, in.From, in, "pass"); err != nil {
		t.Fatal(err)
	}
	files, err := e.srv.st.ListFiles(agent.ID)
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%+v err=%v", files, err)
	}
	if !files[0].Claimed || files[0].ExpiresAt != 0 {
		t.Fatalf("inbound duplicate weakened persistent file: %+v", files[0])
	}
}

func TestDomainOfAddr(t *testing.T) {
	if d := domainOfAddr("agent@agents.example.com"); d != "agents.example.com" {
		t.Fatalf("domainOfAddr = %q", d)
	}
	if d := domainOfAddr("no-at-sign"); d != "" {
		t.Fatalf("domainOfAddr on bare string = %q, want empty", d)
	}
}

func TestInboundPolicyRequiresAuthenticatedSender(t *testing.T) {
	e := newEnv(t)
	_, recipientKey := e.createAgent("policy-recipient")
	senderEmail, _ := e.createAgent("policy-sender")
	recipient, err := e.srv.st.AgentByKey(recipientKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.st.SetPolicy(recipient.ID, "closed", []string{senderEmail}); err != nil {
		t.Fatal(err)
	}
	recipient.AcceptPolicy = "closed"

	if deliver, _ := e.srv.decideInbound(recipient, senderEmail, false); deliver {
		t.Fatal("an unauthenticated external From must not inherit a local agent's allowlist/space trust")
	}
	if deliver, quarantine := e.srv.decideInbound(recipient, senderEmail, true); !deliver || quarantine {
		t.Fatalf("authenticated allowlisted sender: deliver=%v quarantine=%v", deliver, quarantine)
	}
}
