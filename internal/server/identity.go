package server

import (
	"strings"
)

// identityFor computes an agent's visible identity tier from signals we already
// hold. It is the single source of truth for the `identity` object exposed on
// cards, the directory, pubkey lookups, and whoami — so those surfaces can't
// drift apart.
//
// Tiers:
//
//	"instance" — a closed-signup instance asserts the agent under its domain.
//	"owner"    — an owner record has been verified for this specific agent.
//	"keyed"    — neither; the agent is just an API-key identity.
//
// An open-signup domain is a shared public platform, so merely being hosted on
// it is not an organization signal. The basis is explicit and deliberately
// avoids claiming independent TLS, DNS, DKIM, or legal-organization proof.
func (s *Server) identityFor(ownerVerified bool) map[string]any {
	tier := "keyed"
	basis := "api_key"
	if ownerVerified {
		tier = "owner"
		basis = "owner_record"
	}
	if s.cfg.EmailEnabled() && !s.cfg.OpenSignup {
		tier = "instance"
		basis = "closed_instance"
	}
	return map[string]any{
		"tier":     tier,
		"instance": s.st.Instance(),
		"basis":    basis,
	}
}

// senderIdentity surfaces what we can verify about a message's sender: the From
// domain, and whether DKIM authenticated it (aligned pass, or same-instance
// local delivery). It turns the boolean `trusted` we already compute into a
// legible origin signal.
func senderIdentity(dkim, from string) map[string]any {
	domain := ""
	if _, d, ok := strings.Cut(strings.ToLower(from), "@"); ok {
		domain = d
	}
	return map[string]any{
		"domain":          domain,
		"domain_verified": dkim == "pass" || dkim == "local",
	}
}
