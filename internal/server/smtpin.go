package server

import (
	"bytes"
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
	// client to pull and parse itself. Keyed presence, plus the full rcpt
	// list to hand the client.
	connectNames map[string]bool
	connectRcpts []string
}

func (ss *smtpSession) Reset() {
	ss.from = ""
	ss.agents = nil
	ss.connectNames = nil
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
			if ss.connectNames == nil {
				ss.connectNames = map[string]bool{}
			}
			ss.connectNames[name] = true
			ss.connectRcpts = append(ss.connectRcpts, addr)
			return nil
		}
	}

	if domain != ss.s.cfg.Domain {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "relay not permitted"}
	}
	// Accept plus-addressing: name+tag@domain routes to name@domain.
	localpart, _, _ = strings.Cut(localpart, "+")
	agent, err := ss.s.st.AgentByName(localpart)
	if err != nil {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "no such agent"}
	}
	// Repeated RCPTs for the same agent (verbatim duplicates, or plus-tag
	// variants of one address) must not multiply inbox copies.
	for _, a := range ss.agents {
		if a.ID == agent.ID {
			return nil
		}
	}
	ss.agents = append(ss.agents, agent)
	return nil
}

func (ss *smtpSession) Data(r io.Reader) error {
	if len(ss.agents) == 0 && len(ss.connectNames) == 0 {
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
	for name := range ss.connectNames {
		err := ss.s.connect.deliverConnectMail(name, ss.connectRcpts, raw)
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
				return &gosmtp.SMTPError{Code: 451, Message: "temporary ingest failure"}
			}
		}
	}
	ss.s.metrics.inboundMail.Add(1)
	return nil
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

// dkimAligned implements relaxed alignment (as in DMARC): the signing domain
// and the From domain must be equal, or one must be a parent domain of the
// other on a label boundary.
func dkimAligned(sigDomain, fromDomain string) bool {
	d := strings.ToLower(strings.TrimSpace(sigDomain))
	f := strings.ToLower(strings.TrimSpace(fromDomain))
	if d == "" || f == "" {
		return false
	}
	return d == f || strings.HasSuffix(f, "."+d) || strings.HasSuffix(d, "."+f)
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

	for _, a := range in.Attachments {
		// Both storage guards degrade gracefully here: drop the attachment
		// with a note in the body rather than 5xx-ing the SMTP transaction
		// (the message text and manifest always get through).
		if s.diskFull() {
			text += fmt.Sprintf("\n[agenttransfer: attachment %q dropped — instance storage full]", a.Name)
			continue
		}
		used, _ := s.st.StorageUsed(agent.ID)
		if used+int64(len(a.Data)) > s.quotaFor(agent) {
			text += fmt.Sprintf("\n[agenttransfer: attachment %q dropped — storage quota exceeded]", a.Name)
			continue
		}
		sha, size, err := s.st.PutBlob(bytes.NewReader(a.Data), s.cfg.MaxFileSize)
		if err != nil {
			return err
		}
		expires := time.Now().Add(s.cfg.DefaultTTL).Unix()
		f, err := s.st.AddFile(agent.ID, sha, a.Name, a.MIME, size, "inbound", false, expires)
		if err != nil {
			return err
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
	}
	msg, err := s.st.AddMessage(m)
	if err != nil {
		return err
	}
	s.hub.notify(agent.ID)

	sha, size := "", int64(0)
	if len(atts) > 0 {
		sha, size = atts[0].SHA256, atts[0].Size
	}
	agentMsgID := mail.ExtractAgentMessageID(in.MessageID)
	if agentMsgID == "" {
		agentMsgID = msg.ID
	}
	_, _ = s.st.AppendReceipt(agent.Email, receipt.ActionReceived, sha, size, from, agentMsgID)
	return nil
}
