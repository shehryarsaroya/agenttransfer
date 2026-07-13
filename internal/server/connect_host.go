package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	netmail "net/mail"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	afmail "github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// liveInstance loads a registered instance and rejects it if suspended — the
// kill switch must bite on every path, not just the tunnel and proxy.
func (h *connectHost) liveInstance(name string) (store.ConnectInstance, error) {
	ci, err := h.s.st.ConnectInstanceByName(name)
	if err != nil {
		return ci, err
	}
	if ci.Suspended {
		return ci, errSuspended
	}
	return ci, nil
}

var errSuspended = errors.New("instance suspended")

// connectHost is the mothership side: it lends registered instances a public
// subdomain and email service. One live tunnel per instance carries all
// public web traffic (host→client) and control calls (client→host: relay
// outbound mail, drain queued inbound mail).
type connectHost struct {
	s        *Server
	mu       sync.RWMutex
	sessions map[string]*connectSession
}

type connectSession struct {
	name     string
	sess     *yamux.Session
	mailWake chan struct{} // signalled when inbound mail is queued
}

func newConnectHost(s *Server) *connectHost {
	return &connectHost{s: s, sessions: map[string]*connectSession{}}
}

// isConnectSubdomain reports whether host is "<name>.<connectDomain>" and
// returns the single-label name.
func (h *connectHost) isConnectSubdomain(host string) (string, bool) {
	host = strings.ToLower(host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	suffix := "." + h.s.cfg.ConnectDomain
	name, ok := strings.CutSuffix(host, suffix)
	if !ok || name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

func (h *connectHost) online(name string) *connectSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[name]
}

// ---- registration ----

func (h *connectHost) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !h.s.signupLimiter.allow(h.s.clientIP(r)) {
		errJSON(w, http.StatusTooManyRequests, "registration rate limit: try again shortly")
		return
	}
	// A few tries to dodge the rare random-name collision.
	var name, token string
	for i := 0; i < 5; i++ {
		candidate := randomInstanceName()
		t, err := h.s.st.CreateConnectInstance(candidate)
		if err == nil {
			name, token = candidate, t
			break
		}
	}
	if token == "" {
		errJSON(w, http.StatusInternalServerError, "could not allocate a name; retry")
		return
	}
	writeJSON(w, http.StatusCreated, registerResponse{
		Name:       name,
		Token:      token,
		PublicURL:  "https://" + name + "." + h.s.cfg.ConnectDomain,
		AgentEmail: "<agent>@" + name + "." + h.s.cfg.ConnectDomain,
	})
}

// ---- tunnel establishment ----

func (h *connectHost) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), connectUpgrade) {
		http.Error(w, "expected Upgrade: "+connectUpgrade, http.StatusBadRequest)
		return
	}
	ci, err := h.s.st.ConnectInstanceByToken(r.Header.Get(connectTokenHeader))
	if err != nil {
		http.Error(w, "unknown or missing connect token", http.StatusUnauthorized)
		return
	}
	if ci.Suspended {
		http.Error(w, "this instance is suspended", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	// Confirm the upgrade, then the raw conn carries yamux.
	io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+connectUpgrade+"\r\nConnection: Upgrade\r\n\r\n")

	sess, err := yamux.Server(conn, yamuxCfg())
	if err != nil {
		conn.Close()
		return
	}
	cs := &connectSession{name: ci.Name, sess: sess, mailWake: make(chan struct{}, 1)}

	h.mu.Lock()
	if old := h.sessions[ci.Name]; old != nil {
		old.sess.Close() // one tunnel per instance; newest wins
	}
	h.sessions[ci.Name] = cs
	h.mu.Unlock()
	_ = h.s.st.TouchConnectInstance(ci.Name)

	// Serve control calls the client opens on this session until it dies.
	_ = http.Serve(sess, h.controlHandler(cs))

	h.mu.Lock()
	if h.sessions[ci.Name] == cs {
		delete(h.sessions, ci.Name)
	}
	h.mu.Unlock()
	_ = h.s.st.TouchConnectInstance(ci.Name)
	sess.Close()
}

// ---- public subdomain reverse proxy (host → client) ----

func (h *connectHost) proxy(w http.ResponseWriter, r *http.Request, name string) {
	// Internal control paths must never be reachable from the public side.
	if strings.HasPrefix(r.URL.Path, "/connect/") {
		http.NotFound(w, r)
		return
	}
	ci, err := h.s.st.ConnectInstanceByName(name)
	if err != nil {
		h.notHere(w, "No such instance.")
		return
	}
	if ci.Suspended {
		http.Error(w, "This instance has been suspended.", http.StatusForbidden)
		return
	}
	cs := h.online(name)
	if cs == nil {
		h.notHere(w, "This instance is offline right now — its owner's machine isn't connected. Try again later.")
		return
	}
	// Daily egress budget (abuse + cost cap). Reject once already over…
	if used, _ := h.s.st.IncrCounterN(name, "connect_bytes", 0); used > h.s.cfg.ConnectBytesPerDay {
		http.Error(w, "This instance hit its daily transfer limit. Try again tomorrow.", http.StatusServiceUnavailable)
		return
	}

	// …and meter DURING the stream, aborting when the running total crosses
	// the cap, so one huge or many concurrent downloads can't blow past it.
	mw := &meteredWriter{ResponseWriter: w, st: h.s.st, name: name, cap: h.s.cfg.ConnectBytesPerDay}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = name
		},
		Transport:     &tunnelTransport{sess: cs.sess},
		FlushInterval: 200 * time.Millisecond, // stream large downloads
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.notHere(w, "This instance dropped its connection mid-request.")
		},
	}
	rp.ServeHTTP(mw, r)
	mw.flush()
}

func (h *connectHost) notHere(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintln(w, msg)
}

// tunnelTransport turns each outbound request into one yamux stream.
type tunnelTransport struct{ sess *yamux.Session }

func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stream, err := t.sess.Open()
	if err != nil {
		return nil, err
	}
	req.Close = true // one request per stream, no keep-alive
	if err := req.Write(stream); err != nil {
		stream.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		stream.Close()
		return nil, err
	}
	resp.Body = &streamBody{ReadCloser: resp.Body, stream: stream}
	return resp, nil
}

// streamBody closes the underlying yamux stream when the response body closes.
type streamBody struct {
	io.ReadCloser
	stream net.Conn
}

func (b *streamBody) Close() error {
	err := b.ReadCloser.Close()
	b.stream.Close()
	return err
}

// meteredWriter charges proxied response bytes against the instance's daily
// egress budget as they stream, flushing to the counter every ~1 MiB and
// aborting the write once the running total crosses the cap. Overshoot is
// bounded to one flush window per in-flight stream.
type meteredWriter struct {
	http.ResponseWriter
	st      *store.Store
	name    string
	cap     int64
	pending int64 // written but not yet charged
	over    bool
}

var errOverEgress = errors.New("connect: instance egress budget exhausted")

func (c *meteredWriter) Write(p []byte) (int, error) {
	if c.over {
		return 0, errOverEgress
	}
	n, err := c.ResponseWriter.Write(p)
	c.pending += int64(n)
	if c.pending >= 1<<20 {
		c.flush()
	}
	if err == nil && c.over {
		return n, errOverEgress
	}
	return n, err
}

func (c *meteredWriter) flush() {
	if c.pending == 0 {
		return
	}
	total, _ := c.st.IncrCounterN(c.name, "connect_bytes", c.pending)
	c.pending = 0
	if total > c.cap {
		c.over = true
	}
}

func (c *meteredWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---- control channel (client → host) ----

func (h *connectHost) controlHandler(cs *connectSession) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+connectRelayPath, func(w http.ResponseWriter, r *http.Request) {
		h.handleRelay(w, r, cs.name)
	})
	mux.HandleFunc("GET "+connectDrainPath, func(w http.ResponseWriter, r *http.Request) {
		h.handleDrain(w, r, cs)
	})
	mux.HandleFunc("POST "+connectAckPath, func(w http.ResponseWriter, r *http.Request) {
		h.handleAck(w, r, cs.name)
	})
	mux.HandleFunc("POST "+connectVerifyMailPath, func(w http.ResponseWriter, r *http.Request) {
		h.handleVerifyMail(w, r, cs.name)
	})
	return mux
}

// handleRelay sends one outbound email on behalf of a verified instance,
// through the host's own relay. The instance may only send AS ITSELF (From
// must be @<its own subdomain>): the upstream relay signs with the host's
// domain, so an unchecked From would let one tenant emit DKIM-aligned mail
// impersonating a sibling instance or the host apex.
func (h *connectHost) handleRelay(w http.ResponseWriter, r *http.Request, name string) {
	ci, err := h.liveInstance(name)
	if err != nil {
		errJSON(w, http.StatusForbidden, "instance unavailable: %v", err)
		return
	}
	if !ci.Verified {
		errJSON(w, http.StatusForbidden, "outbound email locked: verify an owner email first")
		return
	}
	if h.s.outbound == nil {
		errJSON(w, http.StatusBadGateway, "host has no outbound relay configured")
		return
	}
	var req relayRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, connectMaxRelayBytes)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "bad relay request")
		return
	}
	if len(req.Rcpts) == 0 {
		errJSON(w, http.StatusBadRequest, "no recipients")
		return
	}
	if len(req.Rcpts) > connectMaxRecipients {
		errJSON(w, http.StatusBadRequest, "at most %d recipients per message", connectMaxRecipients)
		return
	}

	instanceDomain := name + "." + h.s.cfg.ConnectDomain
	if !senderIsInstance(req.From, req.Raw, instanceDomain) {
		errJSON(w, http.StatusForbidden, "From must be an address @%s (an instance may only send as itself)", instanceDomain)
		return
	}

	// Charge one unit PER RECIPIENT (matching the API's own send accounting),
	// so the daily cap bounds email volume, not call count. A rejected batch
	// is refunded — bouncing off the cap must not brick smaller sends.
	if err := h.s.checkRateN(name, "connect_sends", int64(len(req.Rcpts)), h.s.cfg.ConnectSendRate); err != nil {
		errJSON(w, http.StatusTooManyRequests, "daily outbound email limit reached for this instance")
		return
	}
	if err := afmail.Send(h.s.outbound, req.From, req.Rcpts, req.Raw); err != nil {
		errJSON(w, http.StatusBadGateway, "relay failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": len(req.Rcpts)})
}

// senderIsInstance verifies both the envelope From and the message's From:
// header belong to instanceDomain.
func senderIsInstance(envelopeFrom string, raw []byte, instanceDomain string) bool {
	if !strings.EqualFold(domainOfAddr(strings.Trim(strings.TrimSpace(envelopeFrom), "<>")), instanceDomain) {
		return false
	}
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	addr, err := netmail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		return false
	}
	return strings.EqualFold(domainOfAddr(addr.Address), instanceDomain)
}

// handleDrain long-polls for queued inbound mail for the instance.
func (h *connectHost) handleDrain(w http.ResponseWriter, r *http.Request, cs *connectSession) {
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	for {
		mail, err := h.s.st.ListConnectMail(cs.name, 50)
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if len(mail) > 0 {
			out := make([]queuedMail, 0, len(mail))
			for _, m := range mail {
				out = append(out, queuedMail{ID: m.ID, Rcpts: m.Rcpts, Raw: m.Raw})
			}
			writeJSON(w, http.StatusOK, drainResponse{Mail: out})
			return
		}
		select {
		case <-cs.mailWake:
		case <-deadline.C:
			writeJSON(w, http.StatusOK, drainResponse{Mail: []queuedMail{}})
			return
		case <-r.Context().Done():
			return
		}
	}
}

// handleAck deletes queued mail the client has durably ingested.
func (h *connectHost) handleAck(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := decodeBody(r, &body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad ack")
		return
	}
	for _, id := range body.IDs {
		_ = h.s.st.DeleteConnectMail(name, id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"acked": len(body.IDs)})
}

// ---- inbound mail intake (called from the SMTP path) ----

// deliverConnectMail queues one raw inbound message for a live instance and
// wakes its drain long-poll if it is online. The error distinguishes a full
// queue (retryable) from an unknown/suspended instance (permanent reject).
func (h *connectHost) deliverConnectMail(name string, rcpts []string, raw []byte) error {
	if _, err := h.liveInstance(name); err != nil {
		return err
	}
	if err := h.s.st.EnqueueConnectMail(name, rcpts, raw, connectQueueMaxMsgs, connectQueueMaxBytes); err != nil {
		return err
	}
	if cs := h.online(name); cs != nil {
		select {
		case cs.mailWake <- struct{}{}:
		default:
		}
	}
	return nil
}

// ---- owner verification (unlocks outbound email) ----

// handleVerifyMail (control channel, tunnel-authenticated) emails the owner
// a magic link for the calling instance. Only the instance itself can
// trigger it, and only a few times a day — it must not be a way to spray
// email at strangers.
func (h *connectHost) handleVerifyMail(w http.ResponseWriter, r *http.Request, name string) {
	if _, err := h.liveInstance(name); err != nil {
		errJSON(w, http.StatusForbidden, "instance unavailable: %v", err)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	addr, err := netmail.ParseAddress(strings.TrimSpace(req.Email))
	if err != nil {
		errJSON(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	email := addr.Address
	if h.s.outbound == nil || !h.s.cfg.EmailEnabled() {
		errJSON(w, http.StatusBadGateway, "host cannot send verification email (no relay configured)")
		return
	}
	if n, _ := h.s.st.IncrCounter(name, "connect_verifymail"); n > connectVerifyMailPerDay {
		errJSON(w, http.StatusTooManyRequests, "too many verification emails today")
		return
	}
	vtok, err := h.s.st.CreateVerifyToken("connect:" + name + ":" + email)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	instance := name + "." + h.s.cfg.ConnectDomain
	link := h.s.BaseURL() + connectVerifyPath + "?t=" + vtok
	m := &afmail.Message{
		FromName: "AgentTransfer", From: "no-reply@" + h.s.cfg.Domain,
		To:      []string{email},
		Subject: "Unlock outbound email for " + instance,
		Text: fmt.Sprintf("Confirm you own this address to let the AgentTransfer instance %q send email:\n\n  %s\n\n"+
			"If this wasn't you, ignore this message.\n", instance, link),
		MessageID: afmail.FormatRFCMessageID(store.NewID("msg"), h.s.cfg.Domain),
	}
	raw, err := m.Build()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := afmail.Send(h.s.outbound, m.From, []string{email}, raw); err != nil {
		errJSON(w, http.StatusBadGateway, "could not send verification email: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification": "sent", "to": email})
}

// handleVerify (GET) is the public landing for the emailed magic link. Like
// the agent flow, the GET consumes nothing — mail-scanner prefetches must not
// be able to verify an instance; only the explicit confirm POST does.
func (h *connectHost) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok := r.URL.Query().Get("t")
	slot, err := h.s.st.PeekVerifyToken(tok)
	if err != nil {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	rest, ok := strings.CutPrefix(slot, "connect:")
	if !ok {
		http.Error(w, "not a connect verification link", http.StatusBadRequest)
		return
	}
	cname, _, _ := strings.Cut(rest, ":")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.s.tmpl.ExecuteTemplate(w, "verify.html", map[string]any{
		"What":   "instance " + cname + "." + h.s.cfg.ConnectDomain,
		"Action": connectVerifyPath + "?t=" + neturl.QueryEscape(tok),
		"Sends":  h.s.cfg.ConnectSendRate,
		"Circle": int64(-1),
	})
}

// handleVerifyConfirm (POST) consumes the token and unlocks outbound email
// for the tunneled instance.
func (h *connectHost) handleVerifyConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tok := r.URL.Query().Get("t")
	if tok == "" {
		tok = r.FormValue("t")
	}
	// Reject a non-connect (agent) token BEFORE consuming, so it isn't burned
	// on the wrong path.
	if slot, err := h.s.st.PeekVerifyToken(tok); err != nil || !strings.HasPrefix(slot, "connect:") {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	agentID, err := h.s.st.ConsumeVerifyToken(tok)
	if err != nil {
		http.Error(w, "verification link is invalid or expired", http.StatusNotFound)
		return
	}
	// The verify token's "agent id" slot carries "connect:<name>:<email>".
	rest, ok := strings.CutPrefix(agentID, "connect:")
	if !ok {
		http.Error(w, "not a connect verification link", http.StatusBadRequest)
		return
	}
	cname, cemail, _ := strings.Cut(rest, ":")
	if err := h.s.st.SetConnectVerified(cname, cemail); err != nil {
		http.Error(w, "verification failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.s.tmpl.ExecuteTemplate(w, "verified.html", map[string]any{"Agent": cname + "." + h.s.cfg.ConnectDomain})
}

// handleSuspend is the operator kill switch for an abusive instance: the
// tunnel is refused, public traffic stops, and inbound mail is rejected.
func (h *connectHost) handleSuspend(w http.ResponseWriter, r *http.Request) {
	if !h.s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	var req struct {
		Name      string `json:"name"`
		Suspended *bool  `json:"suspended"`
	}
	if err := decodeBody(r, &req); err != nil || req.Name == "" || req.Suspended == nil {
		errJSON(w, http.StatusBadRequest, "provide {\"name\": \"...\", \"suspended\": true|false}")
		return
	}
	if err := h.s.st.SetConnectSuspended(req.Name, *req.Suspended); err != nil {
		errJSON(w, http.StatusNotFound, "unknown instance")
		return
	}
	if *req.Suspended {
		h.mu.Lock()
		if cs := h.sessions[req.Name]; cs != nil {
			cs.sess.Close()
			delete(h.sessions, req.Name)
		}
		h.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "suspended": *req.Suspended})
}

// reapLoop periodically evicts dead registrations and their queued mail.
func (h *connectHost) reapLoop(stop <-chan struct{}) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_, _ = h.s.st.ReapConnectInstances(connectGraceNew, connectGraceIdle)
		}
	}
}
