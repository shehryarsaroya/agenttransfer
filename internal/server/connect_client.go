package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/shehryarsaroya/agenttransfer/internal/mail"
)

// connectClient keeps this instance registered with a connect host and holds
// one outbound tunnel open to it. The tunnel makes the instance publicly
// reachable at https://<name>.<host> and carries its email both ways — no
// domain, DNS, open ports, or relay of its own.
type connectClient struct {
	s   *Server
	url string // connect host base URL

	// mu guards the identity (set once at registration by the run loop, read
	// by API handlers) and the live-tunnel state (swapped as the tunnel comes
	// and goes).
	mu        sync.Mutex
	name      string
	token     string
	publicURL string
	control   *http.Client   // opens streams on the live tunnel; nil when down
	session   *yamux.Session // nil when down
}

var errConnectRegistrationGone = errors.New("connect registration expired")

func (c *connectClient) setIdentity(name, token, publicURL string) {
	c.mu.Lock()
	c.name, c.token, c.publicURL = name, token, publicURL
	c.mu.Unlock()
}

func (c *connectClient) identity() (name, token, publicURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.name, c.token, c.publicURL
}

func (c *connectClient) setLive(sess *yamux.Session, ctl *http.Client) {
	c.mu.Lock()
	c.session, c.control = sess, ctl
	c.mu.Unlock()
}

func (c *connectClient) liveControl() *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.control
}

func newConnectClient(s *Server) (*connectClient, error) {
	c := &connectClient{s: s, url: s.cfg.Connect}
	// Resume a prior registration if it was against the same host.
	if savedURL, _ := s.st.GetSetting("connect_url"); savedURL == c.url {
		name, _ := s.st.GetSetting("connect_name")
		token, _ := s.st.GetSetting("connect_token")
		publicURL, _ := s.st.GetSetting("connect_public_url")
		c.setIdentity(name, token, publicURL)
	}
	// A resumed identity must be applied synchronously, before Run opens local
	// listeners. New registrations are applied by the retrying run loop before
	// it attempts their first tunnel.
	if c.registered() {
		if err := c.applyIdentity(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *connectClient) registered() bool {
	name, token, publicURL := c.identity()
	return name != "" && token != "" && publicURL != ""
}

func (c *connectClient) forgetRegistration() {
	c.setIdentity("", "", "")
	// Clear the host marker first: even if the process stops between writes, the
	// next startup will not resume the rejected token.
	for _, key := range []string{"connect_url", "connect_name", "connect_token", "connect_public_url"} {
		_ = c.s.st.SetSetting(key, "")
	}
}

func (c *connectClient) connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil && !c.session.IsClosed()
}

// applyIdentity makes the borrowed public URL this instance's identity:
// base URL for links, instance domain for agent addresses and receipts.
func (c *connectClient) applyIdentity() error {
	_, _, publicURL := c.identity()
	u, err := parseBaseOrigin(publicURL)
	if err != nil || u.Scheme != "https" || u.Port() != "" || !publicURLUnderHost(publicURL, c.url) {
		return fmt.Errorf("invalid connect public URL %q", publicURL)
	}
	instance := strings.ToLower(u.Hostname())
	if err := c.s.st.RenameInstance(instance); err != nil {
		return fmt.Errorf("rename instance to %s: %w", instance, err)
	}
	c.s.SetBaseURL(publicURL)
	return nil
}

// run registers (once), then dials and re-dials the tunnel until ctx ends.
func (c *connectClient) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if !c.registered() {
			if err := c.register(ctx); err != nil {
				log.Printf("connect: registration with %s failed: %v (retrying)", c.url, err)
				sleepCtx(ctx, backoff)
				backoff = min(backoff*2, time.Minute)
				continue
			}
			backoff = time.Second
		}
		// Applying the borrowed domain rewrites every local agent address. Never
		// expose a tunnel whose public origin and stored identity disagree; retry
		// this local transition before attempting the upgrade.
		if err := c.applyIdentity(); err != nil {
			log.Printf("connect: cannot apply registered identity: %v (retrying)", err)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
			continue
		}
		err := c.serveTunnel(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if errors.Is(err, errConnectRegistrationGone) {
				log.Printf("connect: host expired this registration; requesting a fresh identity")
				c.forgetRegistration()
				backoff = time.Second
				continue
			}
			log.Printf("connect: tunnel to %s dropped: %v (reconnecting)", c.url, err)
		}
		sleepCtx(ctx, backoff)
		backoff = min(backoff*2, time.Minute)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (c *connectClient) register(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+connectRegisterPath, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("register: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var reg registerResponse
	if err := json.Unmarshal(body, &reg); err != nil {
		return fmt.Errorf("register: bad response: %w", err)
	}
	if reg.Token == "" || !publicURLUnderHost(reg.PublicURL, c.url) {
		return fmt.Errorf("register: host returned an unexpected identity %q", reg.PublicURL)
	}
	for k, v := range map[string]string{
		"connect_url": c.url, "connect_name": reg.Name,
		"connect_token": reg.Token, "connect_public_url": reg.PublicURL,
	} {
		if err := c.s.st.SetSetting(k, v); err != nil {
			return err
		}
	}
	// Do not make a partially persisted registration live in memory. The run
	// loop applies its identity, and only then is allowed to open the tunnel.
	c.setIdentity(reg.Name, reg.Token, reg.PublicURL)
	log.Printf("connect: registered — this instance is %s", reg.PublicURL)
	return nil
}

// publicURLUnderHost checks the borrowed public URL is an https subdomain of
// the connect host we actually dialed — a defense against a misbehaving or
// spoofed host handing us someone else's origin.
func publicURLUnderHost(publicURL, hostBase string) bool {
	pu, err := parseBaseOrigin(publicURL)
	if err != nil || pu.Scheme != "https" || pu.Port() != "" {
		return false
	}
	hu, err := parseBaseOrigin(hostBase)
	if err != nil {
		return false
	}
	host := strings.ToLower(hu.Hostname())
	if host == "localhost" || net.ParseIP(host) != nil {
		return true // local/dev connect hosts commonly advertise a real DNS name.
	}
	publicHost := strings.ToLower(pu.Hostname())
	return publicHost != host && strings.HasSuffix(publicHost, "."+host)
}

// serveTunnel dials the host, upgrades, and serves proxied public traffic
// over the session until it dies. It also runs the inbound-mail drain loop.
func (c *connectClient) serveTunnel(ctx context.Context) error {
	_, token, publicURL := c.identity()
	conn, err := dialConnectHost(c.url)
	if err != nil {
		return err
	}
	host := conn.hostname

	req := "GET " + connectTunnelPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		connectTokenHeader + ": " + token + "\r\n" +
		"Upgrade: " + connectUpgrade + "\r\n" +
		"Connection: Upgrade\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		conn.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: HTTP %d", errConnectRegistrationGone, resp.StatusCode)
		}
		return fmt.Errorf("tunnel refused: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	sess, err := yamux.Client(&bufferedConn{Conn: conn.Conn, br: br}, yamuxCfg())
	if err != nil {
		conn.Close()
		return err
	}
	c.setLive(sess, &http.Client{Transport: &tunnelTransport{sess: sess}, Timeout: 2 * time.Minute})
	defer func() {
		c.setLive(nil, nil)
		sess.Close()
	}()
	log.Printf("connect: live at %s", publicURL)

	go c.drainLoop(ctx, sess)

	// The host opens one stream per public request; serve them with the full
	// handler. Returns when the session dies.
	err = http.Serve(sess, c.publicHandler())
	if errors.Is(err, yamux.ErrSessionShutdown) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// publicHandler adapts tunneled requests for the local handler: the real
// client IP comes from the last X-Forwarded-For hop (appended by the host's
// proxy and therefore trustworthy).
func (c *connectClient) publicHandler() http.Handler {
	next := c.s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if remoteAddr, ok := connectForwardedRemoteAddr(r.Header.Get("X-Forwarded-For")); ok {
			r.RemoteAddr = remoteAddr
		}
		next.ServeHTTP(w, r)
	})
}

func connectForwardedRemoteAddr(xForwardedFor string) (string, bool) {
	if xForwardedFor == "" {
		return "", false
	}
	parts := strings.Split(xForwardedFor, ",")
	ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1]))
	if ip == nil {
		return "", false
	}
	return net.JoinHostPort(ip.String(), "0"), true
}

// ---- control calls (client → host over the tunnel) ----

// controlURL uses a fixed placeholder host: the transport ignores it and
// opens a stream on the session instead.
func (c *connectClient) controlURL(path string) string { return "http://connect" + path }

// ctlPost issues one control call over the live tunnel, unwrapping the host's
// {"error": …} envelope on failure. All client→host control calls go through
// it so errors surface uniformly.
func (c *connectClient) ctlPost(path string, payload any) error {
	ctl := c.liveControl()
	if ctl == nil {
		return errors.New("connect tunnel is down; try again shortly")
	}
	body, _ := json.Marshal(payload)
	resp, err := ctl.Post(c.controlURL(path), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// relay sends one outbound email through the host.
func (c *connectClient) relay(from string, rcpts []string, raw []byte) error {
	return c.ctlPost(connectRelayPath, relayRequest{From: from, Rcpts: rcpts, Raw: raw})
}

// requestVerifyMail asks the host to send the owner-verification email.
func (c *connectClient) requestVerifyMail(email string) error {
	return c.ctlPost(connectVerifyMailPath, map[string]string{"email": email})
}

// drainLoop long-polls the host for queued inbound mail, ingests it, and
// acks. Store-and-forward: mail that arrived while this machine slept is
// delivered here on reconnect.
func (c *connectClient) drainLoop(ctx context.Context, sess *yamux.Session) {
	ctl := &http.Client{Transport: &tunnelTransport{sess: sess}} // no timeout: long-poll
	for ctx.Err() == nil && !sess.IsClosed() {
		resp, err := ctl.Get(c.controlURL(connectDrainPath))
		if err != nil {
			sleepCtx(ctx, 2*time.Second)
			continue
		}
		var dr drainResponse
		err = json.NewDecoder(io.LimitReader(resp.Body, 128<<20)).Decode(&dr)
		resp.Body.Close()
		if err != nil {
			sleepCtx(ctx, 2*time.Second)
			continue
		}
		var acked []string
		for _, m := range dr.Mail {
			if err := c.ingestRaw(m.Rcpts, m.Raw); err != nil {
				log.Printf("connect: ingest queued mail %s: %v", m.ID, err)
				continue // leave unacked; retried next drain
			}
			acked = append(acked, m.ID)
		}
		if len(acked) > 0 {
			body, _ := json.Marshal(map[string]any{"ids": acked})
			if resp, err := ctl.Post(c.controlURL(connectAckPath), "application/json", bytes.NewReader(body)); err == nil {
				resp.Body.Close()
			}
		}
	}
}

// ingestRaw parses one raw inbound email and delivers it to each recipient
// agent, exactly as the SMTP path would (DKIM verified locally).
func (c *connectClient) ingestRaw(rcpts []string, raw []byte) error {
	in, err := mail.ParseInbound(bytes.NewReader(raw), 25<<20)
	if err != nil {
		return nil // unparseable: drop (acked), like SMTP's 554
	}
	ensureInboundMessageID(in, raw)
	dkimResult := verifyDKIM(raw, domainOfAddr(in.From))
	instance := c.s.st.Instance()
	delivered := map[string]bool{}
	for _, rcpt := range rcpts {
		localpart, domain, ok := strings.Cut(strings.ToLower(rcpt), "@")
		if !ok || domain != instance {
			continue
		}
		// Use exactly the same plus-address/person-fanout resolver as direct
		// SMTP. Stripping '+' and looking up the base name loses specific
		// handle+agent addresses and breaks person delivery.
		for _, agent := range c.s.resolveLocalRecipient(localpart) {
			if delivered[agent.ID] {
				continue
			}
			delivered[agent.ID] = true
			// Drains are at-least-once (an ack can be lost across a tunnel drop);
			// skip a message this agent already holds so re-delivery doesn't
			// duplicate the inbox row or the signed receipt.
			if c.s.st.HasMessageID(agent.ID, in.MessageID) {
				continue
			}
			if err := c.s.ingestInbound(agent, in.From, in, dkimResult); err != nil {
				return err
			}
		}
	}
	c.s.metrics.inboundMail.Add(1)
	return nil
}

// ---- dialing ----

type hostConn struct {
	net.Conn
	hostname string
}

// dialConnectHost opens a TCP(/TLS) connection to the connect host base URL.
// The tunnel upgrade needs HTTP/1.1, so TLS advertises no ALPN.
func dialConnectHost(base string) (*hostConn, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("bad CONNECT url %q: %w", base, err)
	}
	host := u.Hostname()
	port := u.Port()
	switch u.Scheme {
	case "https":
		if port == "" {
			port = "443"
		}
		conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
		if err != nil {
			return nil, err
		}
		return &hostConn{Conn: conn, hostname: host}, nil
	case "http":
		if port == "" {
			port = "80"
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
		if err != nil {
			return nil, err
		}
		return &hostConn{Conn: conn, hostname: host}, nil
	default:
		return nil, fmt.Errorf("CONNECT url must be http(s), got %q", base)
	}
}

// bufferedConn drains bytes the HTTP response reader buffered past the 101
// before handing reads to the raw connection.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.br.Buffered() > 0 {
		return b.br.Read(p)
	}
	return b.Conn.Read(p)
}

// ---- client-side HTTP surface (admin-gated) ----

// handleConnectStatus reports this instance's connect state.
func (s *Server) handleConnectStatus(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	c := s.client
	out := map[string]any{"connect": s.cfg.Connect, "connected": false}
	if c != nil {
		name, _, publicURL := c.identity()
		out["connected"] = c.connected()
		out["name"] = name
		out["public_url"] = publicURL
	}
	writeJSON(w, http.StatusOK, out)
}

// handleConnectVerify asks the host to email the owner a verification link,
// unlocking outbound email for this instance.
func (s *Server) handleConnectVerify(w http.ResponseWriter, r *http.Request) {
	if !s.st.IsAdmin(bearer(r)) {
		errJSON(w, http.StatusForbidden, "admin token required")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	email := ""
	if err := decodeBody(r, &req); err == nil {
		email = strings.TrimSpace(req.Email)
	}
	if email == "" {
		errJSON(w, http.StatusBadRequest, "provide {\"email\": \"you@example.com\"}")
		return
	}
	if s.client == nil {
		errJSON(w, http.StatusBadRequest, "this instance is not using a connect host (set CONNECT)")
		return
	}
	if err := s.client.requestVerifyMail(email); err != nil {
		errJSON(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification": "sent", "to": email})
}
