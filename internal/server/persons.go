package server

import (
	"fmt"
	"net/http"
	"net/mail"
	"strings"

	afmail "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// The person layer: humans are addresses too. dana@instance is the person —
// delivery fans out to every approved agent they own; dana+desktop@instance
// is one agent. Handles activate only after the person's email is verified,
// and every additional machine is approved by its own click, so claiming to
// be someone is exactly as hard as reading their inbox.

// createPersonAgent handles POST /v1/agents with "as" set: create-or-join a
// person. Returns (response map, status, error-ish message handled by caller).
func (s *Server) createPersonAgent(w http.ResponseWriter, r *http.Request, name, as, ownerEmail, pubkey string, isAdmin bool) {
	as = strings.ToLower(strings.TrimSpace(as))
	tag := strings.ToLower(strings.TrimSpace(name))
	if tag == "" {
		errJSON(w, http.StatusBadRequest, `person-owned signup needs both "as" (your handle) and "name" (this agent's tag, e.g. laptop)`)
		return
	}
	if reservedNames[as] && !isAdmin {
		errJSON(w, http.StatusBadRequest, "the handle %q is reserved on this instance", as)
		return
	}

	person, err := s.st.PersonByHandle(as)
	newPerson := false
	switch {
	case err == nil:
		// Joining an existing person. The signup itself proves nothing —
		// approval happens via the click sent to the person's email, so the
		// only requirement here is that the person is real (verified) and,
		// if the caller supplied an owner_email, that it matches.
		if !person.Verified() {
			errJSON(w, http.StatusForbidden, "the handle %q is awaiting its owner's verification — click the email first, then add more agents", as)
			return
		}
		if ownerEmail != "" && !strings.EqualFold(ownerEmail, person.Email) {
			errJSON(w, http.StatusForbidden, "the handle %q belongs to a different owner email", as)
			return
		}
	default:
		// New person: the handle is born with this first agent. owner_email
		// is the person's email and is required — a person IS a verified
		// address; without one there is nothing to verify against.
		if ownerEmail == "" {
			errJSON(w, http.StatusBadRequest, `creating the handle %q needs "owner_email" — the person is that address`, as)
			return
		}
		if _, err := mail.ParseAddress(ownerEmail); err != nil {
			errJSON(w, http.StatusBadRequest, "owner_email must be a valid address")
			return
		}
		person, err = s.st.CreatePerson(as, ownerEmail)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "%v", err)
			return
		}
		newPerson = true
	}

	if max := s.cfg.MaxAgentsPerOwner; max > 0 && !isAdmin {
		if n, err := s.st.CountAgentsByOwner(person.Email); err == nil && n >= max {
			errJSON(w, http.StatusForbidden, "this owner already has %d agents (max %d)", n, max)
			return
		}
	}

	agent, key, err := s.st.CreateAgentForPerson(person, tag)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "%v", err)
		return
	}
	if pubkey != "" {
		if err := s.st.SetPubkey(agent.ID, pubkey); err == nil {
			agent.Pubkey = pubkey
		}
	}
	if isAdmin {
		_ = s.st.MarkOwnerVerified(agent.ID)
		_ = s.st.MarkPersonVerified(person.ID)
		agent.OwnerVerified = true
	}

	verification := "pending"
	if agent.OwnerVerified {
		verification = "not_required"
	} else if s.emailCapable() {
		if err := s.sendJoinEmail(agent, person, newPerson); err == nil {
			verification = "sent"
		}
	}

	note := fmt.Sprintf("you are %s — part of @%s's fleet once the owner approves (verification email sent to the owner)", agent.Email, person.Handle)
	if newPerson {
		note = fmt.Sprintf("you are %s, and @%s is new — one click on the verification email activates both the handle and this agent", agent.Email, person.Handle)
	}
	if agent.OwnerVerified {
		note = fmt.Sprintf("you are %s — approved and part of @%s's fleet", agent.Email, person.Handle)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent_id":       agent.ID,
		"name":           agent.Name,
		"email":          agent.Email,
		"api_key":        key,
		"pubkey":         agent.Pubkey,
		"person":         person.Handle,
		"person_address": person.Handle + "@" + s.st.Instance(),
		"owner_email":    agent.OwnerEmail,
		"owner_verified": agent.OwnerVerified,
		"verification":   verification,
		"note":           note,
		"endpoints": map[string]string{
			"api": s.BaseURL() + "/v1",
			"mcp": s.BaseURL() + "/mcp",
		},
	})
}

// sendJoinEmail is the agent introducing itself to its human — the
// verification email, written in the agent's voice and sent from its own
// address. (System mail to the claimed owner, exempt from the outbound gate
// like all verification mail; the gate is about strangers.)
func (s *Server) sendJoinEmail(agent store.Agent, person store.Person, newPerson bool) error {
	tok, err := s.st.CreateVerifyToken(agent.ID)
	if err != nil {
		return err
	}
	link := s.BaseURL() + "/verify?t=" + tok
	instance := s.st.Instance()

	subject := fmt.Sprintf("%s wants to join your fleet @%s", agent.Name, person.Handle)
	body := fmt.Sprintf("Hi — I'm a new agent asking to join your fleet.\n\n"+
		"    me:        %s\n"+
		"    fleet:     @%s (anything sent to %s@%s reaches your approved agents)\n\n"+
		"Approve me with one click:\n\n  %s\n\n"+
		"If you didn't create me, ignore this — I can't receive at this address,\n"+
		"join the fleet, or email anyone until you approve.\n",
		agent.Email, person.Handle, person.Handle, instance, link)
	if newPerson {
		subject = fmt.Sprintf("I'm set up at %s — one click to vouch for me", agent.Email)
		body = fmt.Sprintf("Hi — I'm your new agent.\n\n"+
			"    me:          %s\n"+
			"    your handle: @%s — after you verify, %s@%s reaches me (and any\n"+
			"                 future agents you approve), and people who know you\n"+
			"                 can address you, not a machine name.\n\n"+
			"Vouch for me with one click:\n\n  %s\n\n"+
			"Until then I can work privately but can't receive at this address or\n"+
			"email anyone. If this wasn't you, ignore this message and the handle\n"+
			"frees itself in 48 hours.\n",
			agent.Email, person.Handle, person.Handle, instance, link)
	}

	m := &afmail.Message{
		FromName:  agent.Name,
		From:      agent.Email,
		To:        []string{person.Email},
		Subject:   subject,
		Text:      body,
		MessageID: afmail.FormatRFCMessageID(store.NewID("msg"), instance),
	}
	raw, err := m.Build()
	if err != nil {
		return err
	}
	return s.sendRaw(m.From, []string{person.Email}, raw)
}

// resolveLocalRecipient maps a localpart to the same-instance agents it
// reaches: an exact agent (flat or plus-named), or a person (fan-out to all
// approved agents — also the fallback for unknown plus-tags, standard
// plus-addressing semantics). Pending agents and unverified persons resolve
// to nothing, indistinguishable from nonexistent.
func (s *Server) resolveLocalRecipient(localpart string) []store.Agent {
	if la, err := s.st.AgentByName(localpart); err == nil {
		if !la.AttachPending() {
			return []store.Agent{la}
		}
		return nil
	}
	base, _, hadTag := strings.Cut(localpart, "+")
	if person, err := s.st.PersonByHandle(base); err == nil && person.Verified() {
		fleet, err := s.st.AgentsByPerson(person.ID, true)
		if err != nil {
			return nil
		}
		return fleet
	}
	// Classic plus-addressing on a flat agent: alice+anything@ → alice@.
	if hadTag {
		if la, err := s.st.AgentByName(base); err == nil && !la.AttachPending() {
			return []store.Agent{la}
		}
	}
	return nil
}

// handlePersonPage renders GET /@handle — the person's public face: handle,
// verified badge, approved agents. Unknown and unverified handles are one
// indistinguishable 404 (the same anti-enumeration rule as agent cards).
func (s *Server) handlePersonPage(w http.ResponseWriter, r *http.Request, handle string) {
	person, err := s.st.PersonByHandle(handle)
	if err != nil || !person.Verified() {
		http.NotFound(w, r)
		return
	}
	agents, err := s.st.AgentsByPerson(person.ID, true)
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	type row struct{ Name, Email string }
	rows := make([]row, 0, len(agents))
	for _, a := range agents {
		rows = append(rows, row{Name: a.Name, Email: a.Email})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "person.html", map[string]any{
		"Handle":   person.Handle,
		"Address":  person.Handle + "@" + s.st.Instance(),
		"Instance": s.st.Instance(),
		"Agents":   rows,
		"Base":     s.BaseURL(),
	})
}
