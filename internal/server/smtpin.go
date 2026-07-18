package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// maxInboundBytes caps a whole inbound message (email reality ≈ 25 MB of
// attachments once base64 overhead is counted).
const maxInboundBytes = 32 << 20

// newSMTPServer builds the inbound-only SMTP listener. AgentTransfer receives
// raw on port 25 (inbound is easy); it never sends from this socket.
func (s *Server) newSMTPServer(tlsCfg *tls.Config) *gosmtp.Server {
	srv := gosmtp.NewServer(&smtpBackend{s: s})
	srv.Addr = s.cfg.SMTPAddr
	srv.Domain = s.cfg.Domain
	srv.MaxMessageBytes = maxInboundBytes
	srv.MaxRecipients = 50
	srv.ReadTimeout = 2 * time.Minute
	srv.WriteTimeout = 2 * time.Minute
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg // advertise STARTTLS with the instance cert
	}
	return srv
}

type smtpBackend struct{ s *Server }

func (b *smtpBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &smtpSession{s: b.s}, nil
}

type smtpSession struct {
	s      *Server
	from   string
	agents []store.Agent
	// connectRcpts collects recipients addressed to tunneled instances
	// (<agent>@<name>.<connectDomain>); their raw mail is queued for the
	// client to pull and parse itself. The map partitions envelope recipients
	// by instance so one tenant never sees another tenant's Bcc/RCPT list.
	connectRcpts map[string][]string
}

func (ss *smtpSession) Reset() {
	ss.from = ""
	ss.agents = nil
	ss.connectRcpts = nil
}

func (ss *smtpSession) Logout() error { return nil }

func (ss *smtpSession) Mail(from string, opts *gosmtp.MailOptions) error {
	ss.from = strings.ToLower(strings.TrimSpace(from))
	return nil
}

func (ss *smtpSession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	addr := strings.ToLower(strings.TrimSpace(to))
	localpart, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "relay not permitted"}
	}

	// Mail for a tunneled connect instance: queue the raw message, let the
	// client parse and deliver it.
	if ss.s.connect != nil {
		if name, ok := ss.s.connect.isConnectSubdomain(domain); ok {
			if _, err := ss.s.st.ConnectInstanceByName(name); err != nil {
				return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "no such instance"}
			}
			if ss.connectRcpts == nil {
				ss.connectRcpts = map[string][]string{}
			}
			// Partition envelope recipients by tenant. Passing the complete
			// RCPT list to every connected instance would disclose Bcc and
			// cross-tenant addressing metadata.
			ss.connectRcpts[name] = append(ss.connectRcpts[name], addr)
			return nil
		}
	}

	if domain != ss.s.cfg.Domain {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "relay not permitted"}
	}
	// Plus-aware resolution: handle+tag@ is an agent's own name; a bare
	// handle@ (or an unknown tag) fans out to the person's approved agents.
	resolved := ss.s.resolveLocalRecipient(localpart)
	if len(resolved) == 0 {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "no such agent"}
	}
	// Repeated RCPTs for the same agent (verbatim duplicates, plus-tag
	// variants, person fan-out overlap) must not multiply inbox copies.
	for _, agent := range resolved {
		dup := false
		for _, a := range ss.agents {
			if a.ID == agent.ID {
				dup = true
				break
			}
		}
		if !dup {
			ss.agents = append(ss.agents, agent)
		}
	}
	return nil
}

func (ss *smtpSession) Data(r io.Reader) error {
	if len(ss.agents) == 0 && len(ss.connectRcpts) == 0 {
		return &gosmtp.SMTPError{Code: 554, Message: "no valid recipients"}
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxInboundBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxInboundBytes {
		return &gosmtp.SMTPError{Code: 552, EnhancedCode: gosmtp.EnhancedCode{5, 3, 4}, Message: "message too large"}
	}

	// Queue raw mail for each tunneled connect instance (client parses it).
	for name, rcpts := range ss.connectRcpts {
		err := ss.s.connect.deliverConnectMail(name, rcpts, raw)
		switch {
		case err == nil:
		case errors.Is(err, store.ErrQueueFull):
			return &gosmtp.SMTPError{Code: 452, EnhancedCode: gosmtp.EnhancedCode{4, 2, 2}, Message: "mailbox full, retry later"}
		default:
			return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "recipient unavailable"}
		}
	}

	if len(ss.agents) > 0 {
		in, err := mail.ParseInbound(bytes.NewReader(raw), 25<<20)
		if err != nil {
			log.Printf("smtp: unparseable message from %s: %v", ss.from, err)
			return &gosmtp.SMTPError{Code: 554, Message: "unparseable message"}
		}
		ensureInboundMessageID(in, raw)
		from := in.From
		if from == "" {
			from = ss.from
		}
		dkimResult := verifyDKIM(raw, domainOfAddr(from))

		for _, agent := range ss.agents {
			// SMTP delivery is at-least-once: a 451 after a partial multi-
			// recipient ingest makes the sender retry the whole message, so
			// skip recipients that already hold this Message-ID (mirrors the
			// connect drain path).
			if ss.s.st.HasMessageID(agent.ID, in.MessageID) {
				continue
			}
			if err := ss.s.ingestInbound(agent, from, in, dkimResult); err != nil {
				log.Printf("smtp: ingest for %s failed: %v", agent.Email, err)
				if errors.Is(err, store.ErrInboxFull) {
					return &gosmtp.SMTPError{Code: 452, EnhancedCode: gosmtp.EnhancedCode{4, 2, 2}, Message: "mailbox full, retry later"}
				}
				return &gosmtp.SMTPError{Code: 451, Message: "temporary ingest failure"}
			}
		}
	}
	ss.s.metrics.inboundMail.Add(1)
	return nil
}

// ensureInboundMessageID gives header-less mail a deterministic per-message
// identity. SMTP and Connect are both at-least-once transports; without this,
// a retry of the same raw message would create another inbox row and receipt.
func ensureInboundMessageID(in *mail.Inbound, raw []byte) {
	if strings.TrimSpace(in.MessageID) != "" {
		return
	}
	sum := sha256.Sum256(raw)
	in.MessageID = fmt.Sprintf("<agenttransfer-sha256-%x@dedup.invalid>", sum)
}

// verifyDKIM reports the DKIM verdict for a raw message. "pass" requires an
// ALIGNED valid signature (one whose signing domain matches the From domain),
// because a valid signature from an unrelated domain (d=attacker.com on a mail
// spoofing From: agent@victim.com) proves nothing about the claimed sender,
// and "pass" is what makes an offer trusted.
func verifyDKIM(raw []byte, fromDomain string) string {
	verifs, err := dkim.Verify(bytes.NewReader(raw))
	if err != nil || len(verifs) == 0 {
		return "none"
	}
	return dkimVerdict(verifs, fromDomain)
}

func dkimVerdict(verifs []*dkim.Verification, fromDomain string) string {
	for _, v := range verifs {
		if v.Err == nil && dkimAligned(v.Domain, fromDomain) {
			return "pass"
		}
	}
	return "fail"
}

// dkimAligned deliberately requires exact domain alignment. A naïve
// parent/subdomain suffix rule is unsafe on shared public suffixes such as
// github.io; exact matching is conservative and sufficient for this trust
// signal without introducing an organizational-domain policy engine.
func dkimAligned(sigDomain, fromDomain string) bool {
	d := strings.ToLower(strings.TrimSpace(sigDomain))
	f := strings.ToLower(strings.TrimSpace(fromDomain))
	if d == "" || f == "" {
		return false
	}
	return d == f
}

func domainOfAddr(addr string) string {
	_, domain, _ := strings.Cut(addr, "@")
	return domain
}

// ingestInbound stores one parsed inbound email for one recipient agent:
// attachments land in the folder unclaimed (they expire unless kept), a
// manifest becomes the message's offer, and the agent gets an inbox entry.
func (s *Server) ingestInbound(agent store.Agent, from string, in *mail.Inbound, dkimResult string) error {
	var atts []store.Attachment
	text := in.Text

	// Apply policy before writing attachment blobs. In particular, a closed
	// inbox must not be fillable by mail that will be rejected. A remote From
	// address counts as an identity only after aligned DKIM validation.
	deliver, quarantined := s.decideInbound(agent, from, dkimResult == "pass")
	if !deliver {
		return nil // silent SMTP acceptance avoids backscatter and enumeration
	}

	// Keep the logical quota check + attachment inserts serialized with HTTP
	// uploads for this agent. Without the same lock, parallel SMTP sessions can
	// each observe the old usage and exceed the quota together.
	uploadMu := s.uploadLock(agent.ID)
	uploadMu.Lock()
	defer uploadMu.Unlock()
	// The caller performs a cheap precheck, but only this recheck is atomic
	// with attachment/message insertion. Concurrent SMTP retries carrying the
	// same Message-ID serialize here and exactly one creates inbox state.
	if s.st.HasMessageID(agent.ID, in.MessageID) {
		return nil
	}
	type addedEntry struct{ sha, name string }
	var added []addedEntry
	committed := false
	defer func() {
		if committed {
			return
		}
		for _, f := range added {
			_, _ = s.st.DeleteFileEntry(agent.ID, f.sha, f.name)
		}
	}()
	for _, a := range in.Attachments {
		// Both storage guards degrade gracefully here: drop the attachment
		// with a note in the body rather than 5xx-ing the SMTP transaction
		// (the message text and manifest always get through).
		if s.diskFull() {
			text += fmt.Sprintf("\n[agenttransfer: attachment %q dropped — instance storage full]", a.Name)
			continue
		}
		sha, size, err := s.st.PutBlob(bytes.NewReader(a.Data), s.cfg.MaxFileSize)
		if errors.Is(err, store.ErrDiskReserve) {
			text += fmt.Sprintf("\n[agenttransfer: attachment %q dropped — instance storage reserve reached]", a.Name)
			continue
		}
		if err != nil {
			return err
		}
		used, err := s.st.StorageUsed(agent.ID)
		if err != nil {
			return fmt.Errorf("read storage usage: %w", err)
		}
		alreadyCharged, err := s.st.AgentUsesStorageBlob(agent.ID, sha)
		if err != nil {
			return fmt.Errorf("inspect storage references: %w", err)
		}
		if !alreadyCharged && !storageAdditionFits(used, size, s.quotaFor(agent)) {
			text += fmt.Sprintf("\n[agenttransfer: attachment %q dropped — storage quota exceeded]", a.Name)
			continue
		}
		expires := time.Now().Add(s.cfg.DefaultTTL).Unix()
		preexisting := s.st.AgentHasFile(agent.ID, sha, a.Name)
		// AddFile's conflict path refreshes expires_at. A repeated attachment
		// should get a full arrival TTL even when identical bytes/name already
		// exist; rollback still removes only rows this message created.
		f, err := s.st.AddFile(agent.ID, sha, a.Name, a.MIME, size, "inbound", false, expires)
		if err != nil {
			return err
		}
		if !preexisting {
			added = append(added, addedEntry{sha: sha, name: f.Name})
		}
		atts = append(atts, store.Attachment{SHA256: sha, Name: f.Name, MIME: a.MIME, Size: size})
	}

	m := store.Message{
		AgentID:     agent.ID,
		From:        from,
		To:          in.To,
		Subject:     in.Subject,
		Text:        text,
		MessageID:   in.MessageID,
		InReplyTo:   in.InReplyTo,
		References:  in.References,
		Manifest:    string(in.Manifest),
		Attachments: atts,
		DKIM:        dkimResult,
		SPF:         "none", // SPF checking is a documented v1.1 item
		Quarantined: quarantined,
	}
	msg, err := s.st.AddMessage(m)
	if err != nil {
		return err
	}
	committed = true
	if !quarantined {
		s.hub.notify(agent.ID)
		s.enqueueWebhooks(agent.ID, "message.received", msg.ID, from)
	}

	sha, size := "", int64(0)
	if len(atts) > 0 {
		sha, size = atts[0].SHA256, atts[0].Size
	}
	agentMsgID := mail.ExtractAgentMessageID(in.MessageID)
	if agentMsgID == "" {
		agentMsgID = msg.ID
	}
	s.appendReceipt(agent.Email, receipt.ActionReceived, sha, size, from, agentMsgID)
	return nil
}
