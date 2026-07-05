package server

import (
	"net/http"
	"strings"
)

// identityFor computes an agent's visible identity tier from signals we already
// hold. It is the single source of truth for the `verified` object exposed on
// cards, the directory, pubkey lookups, and whoami — so those surfaces can't
// drift apart.
//
// Tiers:
//
//	"domain" — a dedicated (non-open-signup) instance on its own attested domain
//	           vouches for its agents by the domain alone: every agent there
//	           belongs to that operator (e.g. bot@doordash.com on doordash.com).
//	"owner"  — a human owner has been verified for this specific agent.
//	"keyed"  — neither; the agent is just a key.
//
// An open-signup domain is a shared public platform, so being hosted on it is
// not an org signal — those agents top out at "owner". The `domain` is always
// shown so a verifier can judge for itself; we never assert a checkmark.
func (s *Server) identityFor(ownerVerified bool) map[string]any {
	domainAttested := s.cfg.EmailEnabled()
	tier := "keyed"
	if ownerVerified {
		tier = "owner"
	}
	if domainAttested && !s.cfg.OpenSignup {
		tier = "domain"
	}
	return map[string]any{
		"tier":            tier,
		"domain":          s.st.Instance(),
		"domain_attested": domainAttested,
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

// handleAgentCard serves an A2A-style Agent Card at /.well-known/agent-card.json
// — a discovery/identity descriptor for the instance, using the A2A schema so
// A2A tooling can read our capabilities and endpoints. It describes our real
// transports (REST + MCP) and does not claim A2A task-protocol support we don't
// implement.
func (s *Server) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	base := s.BaseURL()
	writeJSON(w, http.StatusOK, map[string]any{
		"protocolVersion":    "0.3.0",
		"name":               "agenttransfer",
		"description":        "Open-source file transfer for AI agents: each agent self-provisions an identity, folder, inbox, and email address; send files up to 5GB between agents via content-addressed, hash-verified links; discover peers and coordinate in shared spaces; every action leaves a signed receipt. MCP server at /mcp.",
		"url":                base + "/v1",
		"preferredTransport": "HTTP+JSON",
		"documentationUrl":   base + "/llms.txt",
		"version":            Version,
		"provider": map[string]any{
			"organization": s.st.Instance(),
			"url":          base,
		},
		"capabilities": map[string]any{
			"streaming":         true,
			"pushNotifications": true,
		},
		"defaultInputModes":  []string{"application/json"},
		"defaultOutputModes": []string{"application/json"},
		"securitySchemes": map[string]any{
			"bearer": map[string]any{"type": "http", "scheme": "bearer"},
		},
		"security": []map[string]any{{"bearer": []string{}}},
		"skills": []map[string]any{
			{"id": "transfer", "name": "Transfer files", "description": "Send files up to 5GB to agents or humans; recipients download over HTTPS and verify the sha256.", "tags": []string{"files", "transfer", "sha256"},
				"examples": []string{"send weights.tar.gz to codex-bot@" + s.st.Instance(), "share a 2GB dataset with another agent and verify the hash"}},
			{"id": "inbox", "name": "Receive", "description": "Every agent has an inbox and email address; long-poll or webhook on arrival.", "tags": []string{"messaging", "email"},
				"examples": []string{"wait for the next file to arrive in my inbox"}},
			{"id": "spaces", "name": "Coordinate", "description": "Shared spaces where a fleet of agents exchanges messages and files.", "tags": []string{"coordination", "spaces"},
				"examples": []string{"post scene.blend to the render-fleet space"}},
			{"id": "discovery", "name": "Discover", "description": "Publish a capability card and find peers via the directory.", "tags": []string{"discovery", "directory"},
				"examples": []string{"find an agent that can render"}},
		},
	})
}
