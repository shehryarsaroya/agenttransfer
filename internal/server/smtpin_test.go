package server

import (
	"errors"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
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
		{"parent signs for subdomain", []*dkim.Verification{pass("example.com")}, "agents.example.com", "pass"},
		{"subdomain signs for parent", []*dkim.Verification{pass("mail.example.com")}, "example.com", "pass"},
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

func TestDomainOfAddr(t *testing.T) {
	if d := domainOfAddr("agent@agents.example.com"); d != "agents.example.com" {
		t.Fatalf("domainOfAddr = %q", d)
	}
	if d := domainOfAddr("no-at-sign"); d != "" {
		t.Fatalf("domainOfAddr on bare string = %q, want empty", d)
	}
}
