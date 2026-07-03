package server

import (
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// Shared wire contract between the connect HOST and the connect CLIENT.
//
// The client dials the host, registers (or resumes) an instance, then makes
// ONE long-lived HTTP request to /connect/tunnel that is hijacked into a raw
// bidirectional stream. Over that stream we run yamux:
//
//   - The HOST opens yamux streams to the client, one per inbound public HTTP
//     request; the client serves each with its normal HTTP handler. Bytes
//     flowing back are metered against the instance's daily budget.
//   - The CLIENT opens yamux streams to the host for control calls
//     (outbound email relay, draining queued inbound mail), framed as plain
//     HTTP over the stream.
//
// One TCP connection, TLS-terminated at the host, carries everything: no open
// ports on the client, no second listener.

const (
	// connectTunnelPath is hijacked into the raw yamux carrier.
	connectTunnelPath = "/connect/tunnel"
	// connectRegisterPath registers a new anonymous instance.
	connectRegisterPath = "/connect/register"
	// connectVerifyPath is the owner-verification landing (host side).
	connectVerifyPath = "/connect/verify"

	// Control paths the CLIENT calls on the HOST, over client-opened streams.
	// The tunnel itself authenticates them — no token, no public exposure.
	connectRelayPath      = "/connect/relay"      // POST: relay one outbound email
	connectDrainPath      = "/connect/drain"      // GET: long-poll queued inbound mail
	connectAckPath        = "/connect/ack"        // POST: ack (delete) ingested mail
	connectVerifyMailPath = "/connect/verifymail" // POST: email the owner a verify link

	// Header carrying the instance token on tunnel + control requests.
	connectTokenHeader = "X-Connect-Token"
	// connectUpgrade is the Upgrade token for the hijacked tunnel.
	connectUpgrade = "agenttransfer-tunnel"
)

// Host-side operational limits.
const (
	connectQueueMaxMsgs     = 100      // queued inbound messages per instance
	connectQueueMaxBytes    = 64 << 20 // queued inbound bytes per instance
	connectMaxRelayBytes    = 40 << 20 // max size of one relayed outbound email
	connectMaxRecipients    = 20       // recipients per relayed message
	connectVerifyMailPerDay = 5        // owner-verification emails per instance/day
	connectGraceNew         = 24 * time.Hour
	connectGraceIdle        = 30 * 24 * time.Hour
)

// yamuxCfg returns tuned yamux settings with keepalives on.
func yamuxCfg() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 30 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	c.LogOutput = io.Discard
	return c
}

// registerResponse is returned by /connect/register.
type registerResponse struct {
	Name       string `json:"name"`        // assigned subdomain label
	Token      string `json:"token"`       // instance token (store it; shown once)
	PublicURL  string `json:"public_url"`  // https://<name>.<host domain>
	AgentEmail string `json:"agent_email"` // example address form: <agent>@<name>.<host>
}

// relayRequest is the client→host outbound-email control call body.
type relayRequest struct {
	From  string   `json:"from"`
	Rcpts []string `json:"rcpts"`
	Raw   []byte   `json:"raw"`
}

// drainResponse returns queued inbound mail for a reconnecting instance.
type drainResponse struct {
	Mail []queuedMail `json:"mail"`
}

type queuedMail struct {
	ID    string   `json:"id"`
	Rcpts []string `json:"rcpts"`
	Raw   []byte   `json:"raw"`
}
