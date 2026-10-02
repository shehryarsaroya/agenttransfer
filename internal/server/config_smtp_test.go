package server

import "testing"

// SMTP_ADDR=off must survive ApplyDefaults running more than once (FromEnv
// applies defaults, and New applies them again).
func TestSMTPOffSurvivesRepeatedDefaults(t *testing.T) {
	c := Config{Domain: "agents.example.com", SMTPAddr: "off", BehindProxy: true}
	c.ApplyDefaults()
	c.ApplyDefaults()
	if c.SMTPAddr != "" {
		t.Fatalf("SMTPAddr = %q, want disabled", c.SMTPAddr)
	}
	d := Config{Domain: "agents.example.com", BehindProxy: true}
	d.ApplyDefaults()
	d.ApplyDefaults()
	if d.SMTPAddr != ":25" {
		t.Fatalf("default SMTPAddr = %q, want :25", d.SMTPAddr)
	}
}
