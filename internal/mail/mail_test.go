package mail

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Build → ParseInbound round trip: what one instance sends, another must
// recover intact — headers, note text, and the manifest byte-for-byte.
func TestBuildParseRoundTrip(t *testing.T) {
	manifest := []byte(`{"v":1,"from":"alice@agents.test","message_id":"msg_ab","parts":[{"kind":"text","text":"hi"}]}`)
	m := &Message{
		FromName:     "alice",
		From:         "alice@agents.test",
		To:           []string{"bob@other.test"},
		Subject:      "Résumé — weights.tar.gz",
		Text:         "training set v3\nverify before use\n",
		MessageID:    "<msg_ab@agents.test>",
		InReplyTo:    "<msg_prev@agents.test>",
		References:   "<msg_prev@agents.test>",
		Manifest:     manifest,
		ManifestName: "agenttransfer.json",
	}
	raw, err := m.Build()
	if err != nil {
		t.Fatal(err)
	}

	in, err := ParseInbound(bytes.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if in.From != "alice@agents.test" {
		t.Fatalf("From = %q", in.From)
	}
	if in.Subject != m.Subject {
		t.Fatalf("Subject = %q, want %q (encoded-word round trip)", in.Subject, m.Subject)
	}
	if !strings.Contains(in.Text, "training set v3") || !strings.Contains(in.Text, "verify before use") {
		t.Fatalf("Text = %q", in.Text)
	}
	if !bytes.Equal(in.Manifest, manifest) {
		t.Fatalf("Manifest = %q, want %q", in.Manifest, manifest)
	}
	if in.MessageID != m.MessageID || in.InReplyTo != m.InReplyTo || in.References != m.References {
		t.Fatalf("threading headers lost: %q %q %q", in.MessageID, in.InReplyTo, in.References)
	}
	if len(in.To) != 1 || in.To[0] != "bob@other.test" {
		t.Fatalf("To = %v", in.To)
	}
	if len(in.Attachments) != 0 {
		t.Fatalf("the manifest must not surface as an attachment: %v", in.Attachments)
	}
}

// A plain (no-manifest) build stays a simple text/plain message and parses.
func TestBuildPlainText(t *testing.T) {
	m := &Message{From: "a@x.test", To: []string{"b@y.test"}, Subject: "hello", Text: "just words"}
	raw, err := m.Build()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("multipart")) {
		t.Fatalf("plain message should not be multipart:\n%s", raw)
	}
	in, err := ParseInbound(bytes.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if in.Text != "just words" {
		t.Fatalf("Text = %q", in.Text)
	}
}

// Hand-crafted mail from the wild: base64 attachment, text+html alternative,
// manifest detected by filename when the content type is generic.
func TestParseInboundAttachmentsAndAlternative(t *testing.T) {
	payload := []byte("attachment bytes \x00\x01\x02")
	b64 := base64.StdEncoding.EncodeToString(payload)
	raw := strings.Join([]string{
		"From: Carol <carol@wild.test>",
		"To: agent@agents.test",
		"Subject: mixed bag",
		"Message-Id: <abc123@wild.test>",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="OUTER"`,
		"",
		"--OUTER",
		`Content-Type: multipart/alternative; boundary="INNER"`,
		"",
		"--INNER",
		"Content-Type: text/plain",
		"",
		"the plain body",
		"--INNER",
		"Content-Type: text/html",
		"",
		"<b>the html body</b>",
		"--INNER--",
		"--OUTER",
		"Content-Type: application/octet-stream",
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="data.bin"`,
		"",
		b64,
		"--OUTER",
		"Content-Type: application/json",
		`Content-Disposition: attachment; filename="agenttransfer.json"`,
		"",
		`{"v":1,"from":"carol@wild.test","parts":[]}`,
		"--OUTER--",
		"",
	}, "\r\n")

	in, err := ParseInbound(strings.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if in.From != "carol@wild.test" {
		t.Fatalf("From = %q", in.From)
	}
	if !strings.Contains(in.Text, "the plain body") || strings.Contains(in.Text, "html body") {
		t.Fatalf("text/plain must win over html: %q", in.Text)
	}
	if len(in.Attachments) != 1 || in.Attachments[0].Name != "data.bin" {
		t.Fatalf("attachments = %+v", in.Attachments)
	}
	if !bytes.Equal(in.Attachments[0].Data, payload) {
		t.Fatalf("base64 attachment corrupted: %q", in.Attachments[0].Data)
	}
	if !strings.Contains(string(in.Manifest), `"v":1`) {
		t.Fatalf("manifest by filename not detected: %q", in.Manifest)
	}
}

// Oversized attachments are skipped; the text still comes through.
func TestParseInboundOversizedAttachmentSkipped(t *testing.T) {
	big := strings.Repeat("A", 4096)
	raw := strings.Join([]string{
		"From: carol@wild.test",
		"To: agent@agents.test",
		"Subject: too big",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="B"`,
		"",
		"--B",
		"Content-Type: text/plain",
		"",
		"note survives",
		"--B",
		"Content-Type: application/octet-stream",
		`Content-Disposition: attachment; filename="huge.bin"`,
		"",
		big,
		"--B--",
		"",
	}, "\r\n")
	in, err := ParseInbound(strings.NewReader(raw), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Attachments) != 0 {
		t.Fatalf("oversized attachment kept: %+v", in.Attachments)
	}
	if !strings.Contains(in.Text, "note survives") {
		t.Fatalf("text lost: %q", in.Text)
	}
}

func TestParseInboundAttachmentDispositionIsCaseInsensitive(t *testing.T) {
	raw := strings.Join([]string{
		"From: sender@example.test",
		"To: agent@agents.test",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="B"`,
		"",
		"--B",
		"Content-Type: text/plain",
		"",
		"visible body",
		"--B",
		"Content-Type: text/plain",
		`Content-Disposition: Attachment; filename="instructions.txt"`,
		"",
		"attachment text must not become the body",
		"--B--",
		"",
	}, "\r\n")
	in, err := ParseInbound(strings.NewReader(raw), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if in.Text != "visible body" {
		t.Fatalf("body = %q", in.Text)
	}
	if len(in.Attachments) != 1 || in.Attachments[0].Name != "instructions.txt" ||
		!bytes.Contains(in.Attachments[0].Data, []byte("must not become")) {
		t.Fatalf("attachments = %+v", in.Attachments)
	}
}

func TestExtractAgentMessageID(t *testing.T) {
	cases := map[string]string{
		"<msg_abc@agents.test>": "msg_abc",
		"msg_abc":               "msg_abc",
		"<other@agents.test>":   "",
		"":                      "",
	}
	for in, want := range cases {
		if got := ExtractAgentMessageID(in); got != want {
			t.Errorf("ExtractAgentMessageID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseOutbound(t *testing.T) {
	o, err := ParseOutbound("resend:re_secret")
	if err != nil || o.Host != "smtp.resend.com:587" || o.User != "resend" || o.Pass != "re_secret" || o.Implicit {
		t.Fatalf("resend sugar: %+v err=%v", o, err)
	}
	o, err = ParseOutbound("smtp://u:p@mail.host.test")
	if err != nil || o.Host != "mail.host.test:587" || o.User != "u" || o.Pass != "p" || o.Implicit {
		t.Fatalf("smtp default port: %+v err=%v", o, err)
	}
	o, err = ParseOutbound("smtps://u:p@mail.host.test")
	if err != nil || o.Host != "mail.host.test:465" || !o.Implicit {
		t.Fatalf("smtps default port: %+v err=%v", o, err)
	}
	o, err = ParseOutbound("smtp://u:p@mail.host.test:2525")
	if err != nil || o.Host != "mail.host.test:2525" {
		t.Fatalf("explicit port: %+v err=%v", o, err)
	}
	o, err = ParseOutbound("smtp://u:p@[2001:db8::1]:2525")
	if err != nil || o.HostOnly != "2001:db8::1" || o.Host != "[2001:db8::1]:2525" {
		t.Fatalf("IPv6 explicit port: %+v err=%v", o, err)
	}
	o, err = ParseOutbound("smtps://u:p@[2001:db8::2]")
	if err != nil || o.Host != "[2001:db8::2]:465" {
		t.Fatalf("IPv6 default port: %+v err=%v", o, err)
	}
	for _, bad := range []string{"", "garbage", "http://not.smtp", "smtp://:587", "smtp://mail.host.test:0", "smtp://mail.host.test:65536"} {
		if _, err := ParseOutbound(bad); err == nil {
			t.Errorf("ParseOutbound(%q) should fail", bad)
		}
	}
}
