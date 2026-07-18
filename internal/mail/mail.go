// Package mail builds and sends AgentTransfer's outbound email and parses
// inbound email.
//
// Outbound messages are ordinary multipart/mixed emails: a human-readable
// text body plus the machine-readable AgentTransfer manifest attached as
// application/vnd.agenttransfer+json. Sending goes through the operator's
// relay (any SMTP submission endpoint — Resend, SES, Postmark, ...);
// AgentTransfer never sends from its own IP.
package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	relayDialTimeout = 15 * time.Second
	relayDeadline    = 2 * time.Minute
)

// Outbound is a parsed OUTBOUND relay configuration.
type Outbound struct {
	Host     string // host:port
	HostOnly string
	User     string
	Pass     string
	Implicit bool // smtps:// — implicit TLS instead of STARTTLS
}

// ParseOutbound parses an OUTBOUND value:
//
//	resend:re_xxxx                     (sugar for Resend's SMTP endpoint)
//	smtp://user:pass@host:587          (STARTTLS submission)
//	smtps://user:pass@host:465         (implicit TLS)
func ParseOutbound(s string) (*Outbound, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty OUTBOUND")
	}
	if key, ok := strings.CutPrefix(s, "resend:"); ok {
		return &Outbound{Host: "smtp.resend.com:587", HostOnly: "smtp.resend.com", User: "resend", Pass: key}, nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "smtp" && u.Scheme != "smtps") || u.Host == "" {
		return nil, fmt.Errorf("OUTBOUND must be resend:<key>, smtp://user:pass@host:port or smtps://... (got %q)", s)
	}
	o := &Outbound{Implicit: u.Scheme == "smtps"}
	o.HostOnly = u.Hostname()
	if strings.TrimSpace(o.HostOnly) == "" {
		return nil, fmt.Errorf("OUTBOUND SMTP URL must include a host")
	}
	port := u.Port()
	if port == "" {
		if o.Implicit {
			port = "465"
		} else {
			port = "587"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("OUTBOUND SMTP URL has invalid port %q", port)
	}
	o.Host = net.JoinHostPort(o.HostOnly, port)
	if u.User != nil {
		o.User = u.User.Username()
		o.Pass, _ = u.User.Password()
	}
	return o, nil
}

// Message is an outbound email under construction.
type Message struct {
	FromName   string
	From       string
	To         []string
	CC         []string
	Subject    string
	Text       string
	MessageID  string // full RFC id, e.g. <msg_x@domain>
	InReplyTo  string
	References string
	// Manifest is attached as application/vnd.agenttransfer+json when set.
	Manifest     []byte
	ManifestName string
}

// Build renders the message to raw RFC 5322 bytes.
func (m *Message) Build() ([]byte, error) {
	var buf bytes.Buffer
	var mp *multipart.Writer

	h := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	from := m.From
	if m.FromName != "" {
		from = (&mail.Address{Name: m.FromName, Address: m.From}).String()
	}
	h("From", from)
	h("To", strings.Join(m.To, ", "))
	h("Cc", strings.Join(m.CC, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", m.MessageID)
	h("In-Reply-To", m.InReplyTo)
	h("References", m.References)
	h("MIME-Version", "1.0")

	if len(m.Manifest) == 0 {
		h("Content-Type", `text/plain; charset="utf-8"`)
		h("Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		qp := quotedprintable.NewWriter(&buf)
		if _, err := qp.Write([]byte(m.Text)); err != nil {
			return nil, err
		}
		qp.Close()
		return buf.Bytes(), nil
	}

	mp = multipart.NewWriter(&buf)
	h("Content-Type", `multipart/mixed; boundary="`+mp.Boundary()+`"`)
	buf.WriteString("\r\n")

	// Human-readable body.
	th := textproto.MIMEHeader{}
	th.Set("Content-Type", `text/plain; charset="utf-8"`)
	th.Set("Content-Transfer-Encoding", "quoted-printable")
	tw, err := mp.CreatePart(th)
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(tw)
	if _, err := qp.Write([]byte(m.Text)); err != nil {
		return nil, err
	}
	qp.Close()

	// Machine-readable manifest.
	name := m.ManifestName
	if name == "" {
		name = "agenttransfer.json"
	}
	ah := textproto.MIMEHeader{}
	ah.Set("Content-Type", "application/vnd.agenttransfer+json")
	ah.Set("Content-Transfer-Encoding", "base64")
	ah.Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	aw, err := mp.CreatePart(ah)
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(m.Manifest)
	for len(enc) > 0 {
		n := 76
		if len(enc) < n {
			n = len(enc)
		}
		if _, err := io.WriteString(aw, enc[:n]+"\r\n"); err != nil {
			return nil, err
		}
		enc = enc[n:]
	}
	if err := mp.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Send submits raw message bytes through the relay for the given envelope.
func Send(o *Outbound, envelopeFrom string, rcpts []string, raw []byte) error {
	c, err := dialRelay(o)
	if err != nil {
		return fmt.Errorf("relay connect: %w", err)
	}
	defer c.Close()

	if err := secureRelay(c, o); err != nil {
		return err
	}
	if o.User != "" {
		if err := c.Auth(smtp.PlainAuth("", o.User, o.Pass, o.HostOnly)); err != nil {
			return fmt.Errorf("relay auth: %w", err)
		}
	}
	if err := c.Mail(envelopeFrom); err != nil {
		return fmt.Errorf("relay MAIL FROM: %w", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("relay RCPT %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("relay DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("relay write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("relay send: %w", err)
	}
	return c.Quit()
}

// TestAuth connects and authenticates against the relay without sending —
// used by `agenttransfer doctor`.
func TestAuth(o *Outbound) error {
	c, err := dialRelay(o)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := secureRelay(c, o); err != nil {
		return err
	}
	if o.User != "" {
		if err := c.Auth(smtp.PlainAuth("", o.User, o.Pass, o.HostOnly)); err != nil {
			return err
		}
	}
	return c.Quit()
}

func dialRelay(o *Outbound) (*smtp.Client, error) {
	if o == nil {
		return nil, errors.New("nil outbound relay")
	}
	conn, err := (&net.Dialer{Timeout: relayDialTimeout, KeepAlive: 30 * time.Second}).Dial("tcp", o.Host)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(relayDeadline)); err != nil {
		return nil, err
	}
	if o.Implicit {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: o.HostOnly, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	c, err := smtp.NewClient(conn, o.HostOnly)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return c, nil
}

func secureRelay(c *smtp.Client, o *Outbound) error {
	if o.Implicit {
		return nil
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		if !isLoopbackRelay(o.HostOnly) {
			return errors.New("relay refused: STARTTLS is required for non-loopback smtp:// endpoints")
		}
		return nil // local test/development sink
	}
	if err := c.StartTLS(&tls.Config{ServerName: o.HostOnly, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("relay starttls: %w", err)
	}
	return nil
}

func isLoopbackRelay(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// InAttachment is one attachment from an inbound email.
type InAttachment struct {
	Name string
	MIME string
	Data []byte
}

// Inbound is a parsed inbound email.
type Inbound struct {
	From        string
	To          []string
	Subject     string
	Text        string
	MessageID   string
	InReplyTo   string
	References  string
	Manifest    []byte // raw agenttransfer.json bytes, if present
	Attachments []InAttachment
}

// ParseInbound parses a raw inbound message. Attachments larger than
// maxAttachment bytes are skipped (the text and manifest are always kept).
func ParseInbound(r io.Reader, maxAttachment int64) (*Inbound, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}
	in := &Inbound{
		MessageID:  strings.TrimSpace(msg.Header.Get("Message-Id")),
		InReplyTo:  strings.TrimSpace(msg.Header.Get("In-Reply-To")),
		References: strings.TrimSpace(msg.Header.Get("References")),
	}
	dec := new(mime.WordDecoder)
	if s, err := dec.DecodeHeader(msg.Header.Get("Subject")); err == nil {
		in.Subject = s
	} else {
		in.Subject = msg.Header.Get("Subject")
	}
	if a, err := mail.ParseAddress(msg.Header.Get("From")); err == nil {
		in.From = a.Address
	} else {
		in.From = strings.TrimSpace(msg.Header.Get("From"))
	}
	if list, err := msg.Header.AddressList("To"); err == nil {
		for _, a := range list {
			in.To = append(in.To, a.Address)
		}
	}

	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	if err := walkPart(in, ct, msg.Header.Get("Content-Transfer-Encoding"), "", msg.Body, maxAttachment, 0); err != nil {
		return nil, err
	}
	return in, nil
}

func walkPart(in *Inbound, contentType, encoding, disposition string, body io.Reader, maxAttachment int64, depth int) error {
	if depth > 8 {
		return nil // refuse pathological nesting
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "application/octet-stream"
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return errors.New("multipart without boundary")
		}
		mr := multipart.NewReader(body, boundary)
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return nil // tolerate ragged MIME from the wild
			}
			cd := p.Header.Get("Content-Disposition")
			if err := walkPart(in, p.Header.Get("Content-Type"), p.Header.Get("Content-Transfer-Encoding"), cd, p, maxAttachment, depth+1); err != nil {
				return err
			}
		}
	}

	decoded := decodeBody(body, encoding)
	filename := partFilename(contentType, disposition)
	dispositionType := ""
	if parsed, _, err := mime.ParseMediaType(disposition); err == nil {
		dispositionType = strings.ToLower(parsed)
	}
	isAttachment := dispositionType == "attachment"

	switch {
	case mediaType == "application/vnd.agenttransfer+json" || filename == "agenttransfer.json":
		data, err := io.ReadAll(io.LimitReader(decoded, 1<<20))
		if err == nil {
			in.Manifest = data
		}
	case mediaType == "text/plain" && !isAttachment:
		data, err := io.ReadAll(io.LimitReader(decoded, 1<<20))
		if err == nil {
			if in.Text != "" {
				in.Text += "\n"
			}
			in.Text += strings.TrimRight(string(data), "\r\n")
		}
	case mediaType == "text/html" && filename == "" && !isAttachment:
		// HTML alternative of the body: ignored (text part preferred).
	default:
		if filename == "" && !isAttachment {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(decoded, maxAttachment+1))
		if err != nil || int64(len(data)) > maxAttachment {
			return nil // oversized or unreadable attachment: skip
		}
		name := filename
		if name == "" {
			name = "attachment.bin"
		}
		in.Attachments = append(in.Attachments, InAttachment{Name: name, MIME: mediaType, Data: data})
	}
	return nil
}

func partFilename(contentType, disposition string) string {
	if disposition != "" {
		if _, params, err := mime.ParseMediaType(disposition); err == nil {
			if f := params["filename"]; f != "" {
				return f
			}
		}
	}
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		if f := params["name"]; f != "" {
			return f
		}
	}
	return ""
}

func decodeBody(r io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, newB64Cleaner(r))
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default:
		return r
	}
}

// b64Cleaner strips CR/LF so base64 bodies with line wrapping decode cleanly.
type b64Cleaner struct{ r io.Reader }

func newB64Cleaner(r io.Reader) io.Reader { return &b64Cleaner{r} }

func (c *b64Cleaner) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		w := 0
		for _, b := range p[:n] {
			if b != '\r' && b != '\n' {
				p[w] = b
				w++
			}
		}
		n = w
	}
	return n, err
}

// FormatRFCMessageID renders an AgentTransfer message id as an RFC Message-ID.
func FormatRFCMessageID(msgID, domain string) string {
	return "<" + msgID + "@" + domain + ">"
}

// ExtractAgentMessageID pulls an AgentTransfer "msg_..." id out of an RFC
// Message-ID like "<msg_abc@host>", or returns "".
func ExtractAgentMessageID(rfcID string) string {
	s := strings.Trim(strings.TrimSpace(rfcID), "<>")
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "msg_") {
		return s
	}
	return ""
}
