package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the operator-facing configuration, read from environment
// variables. Everything has a working default; a bare `agenttransfer serve`
// runs a full local instance.
type Config struct {
	// Domain enables email + autocert, e.g. "agents.example.com".
	Domain string
	// DataDir holds the SQLite database and blob directory.
	DataDir string
	// HTTPAddr is the HTTP(S) listen address. Defaults to ":443" when Domain
	// is set (autocert) and ":8080" otherwise.
	HTTPAddr string
	// SMTPAddr is the inbound SMTP listen address (":25" when Domain is set;
	// empty disables).
	SMTPAddr string
	// Outbound is the relay: "resend:<key>", "smtp://user:pass@host:587" or
	// "smtps://...". Empty disables outbound email.
	Outbound string
	// AdminToken gates signup and admin endpoints. Generated and printed on
	// first boot if unset.
	AdminToken string
	// OpenSignup allows unauthenticated signup (rate-limited per IP, owner
	// email verification required before outbound send).
	OpenSignup bool
	// PublicURL overrides the advertised base URL (useful behind a proxy).
	PublicURL string
	// ACMEEmail is the optional Let's Encrypt account email.
	ACMEEmail string
	// BehindProxy disables autocert and trusts X-Forwarded-For.
	BehindProxy bool

	// Connect (client side): URL of a connect host to borrow a public
	// subdomain and email service from, e.g. "https://agenttransfer.dev".
	// The instance registers anonymously, keeps one outbound tunnel open,
	// and needs no domain, DNS, open ports, or relay of its own.
	Connect string
	// ConnectDomain (host side): serve the connect service for
	// "*.<ConnectDomain>" subdomains. Requires Domain mode (TLS + SMTP);
	// usually set equal to Domain.
	ConnectDomain string
	// ConnectSendRate caps relayed outbound emails per connected instance
	// per day (spam blast radius).
	ConnectSendRate int64
	// ConnectBytesPerDay caps proxied bytes per connected instance per day
	// (egress cost + abuse blast radius).
	ConnectBytesPerDay int64

	MaxFileSize  int64
	DefaultTTL   time.Duration
	MaxTTL       time.Duration
	SendRate     int64 // outbound emails per agent per day
	UploadRate   int64 // uploads per agent per day
	StorageQuota int64 // live folder bytes per agent
	// StorageQuotaUnverified is the folder cap for agents whose owner has not
	// verified yet — anonymous signups get a small drive until a human vouches.
	StorageQuotaUnverified int64
	// HumanRecipientsMax caps the unique remote (non-local) addresses an agent
	// may ever email — the "circle": a compromised agent can spam at most this
	// many strangers. The verified owner is always exempt; <0 disables the cap.
	HumanRecipientsMax int64
	Metrics            string // off | localhost | admin

	// DiskReserve is the global backstop against disk fill: uploads are
	// refused (507) while the volume holding DataDir has less free space than
	// this. "10%" of the volume, an absolute size like "50GB", or "off".
	// Applied only when set — FromEnv defaults it to "10%"; hand-built configs
	// (tests, demo) leave it off unless they opt in.
	DiskReserve string
	// MaxAgentsPerOwner caps how many agents one owner_email can register via
	// open signup — identities must not be free in bulk. <0 disables.
	MaxAgentsPerOwner int64
	// IPRate is the per-IP hourly request budget on the public unauthenticated
	// pages (/f/, /u/, index). IPv4 keys per address, IPv6 per /64. <=0
	// disables — FromEnv defaults it to 600.
	IPRate int64
	// UploadBodyTimeout bounds how long one upload request may spend sending
	// its body (slow-body parking defense). It is a read deadline only —
	// downloads deliberately have no write timeout. <=0 disables — FromEnv
	// defaults it to 1h.
	UploadBodyTimeout time.Duration
	// UnverifiedFileTTL makes files owned by agents WITHOUT a verified owner
	// expire — the storage mirror of the quota tier: anonymous signups get a
	// scratchpad, verified owners get the drive. Verifying lifts the expiry
	// on the agent's existing files. <=0 disables — FromEnv defaults it
	// to 24h.
	UnverifiedFileTTL time.Duration
}

// FromEnv builds a Config from the environment.
func FromEnv() (Config, error) {
	c := Config{
		Domain:      strings.TrimSpace(os.Getenv("DOMAIN")),
		DataDir:     envOr("DATA_DIR", "./data"),
		HTTPAddr:    os.Getenv("HTTP_ADDR"),
		SMTPAddr:    os.Getenv("SMTP_ADDR"),
		Outbound:    strings.TrimSpace(os.Getenv("OUTBOUND")),
		AdminToken:  strings.TrimSpace(os.Getenv("ADMIN_TOKEN")),
		OpenSignup:  envBool("OPEN_SIGNUP"),
		PublicURL:   strings.TrimRight(strings.TrimSpace(os.Getenv("PUBLIC_URL")), "/"),
		ACMEEmail:   strings.TrimSpace(os.Getenv("ACME_EMAIL")),
		BehindProxy: envBool("BEHIND_PROXY"),
		Metrics:     envOr("METRICS", "localhost"),

		Connect:       strings.TrimRight(strings.TrimSpace(os.Getenv("CONNECT")), "/"),
		ConnectDomain: strings.ToLower(strings.TrimSpace(os.Getenv("CONNECT_DOMAIN"))),

		DiskReserve: envOr("DISK_RESERVE", "10%"),
	}
	var err error
	if c.ConnectSendRate, err = parseIntEnv("CONNECT_SEND_RATE", 50); err != nil {
		return c, err
	}
	if c.ConnectBytesPerDay, err = parseSizeEnv("CONNECT_BYTES_PER_DAY", "5GB"); err != nil {
		return c, err
	}
	if c.MaxFileSize, err = parseSizeEnv("MAX_FILE_SIZE", "5GB"); err != nil {
		return c, err
	}
	if c.StorageQuota, err = parseSizeEnv("STORAGE_QUOTA", "20GB"); err != nil {
		return c, err
	}
	if c.StorageQuotaUnverified, err = parseSizeEnv("STORAGE_QUOTA_UNVERIFIED", "200MB"); err != nil {
		return c, err
	}
	if c.HumanRecipientsMax, err = parseIntEnv("HUMAN_RECIPIENTS_MAX", 3); err != nil {
		return c, err
	}
	if c.MaxAgentsPerOwner, err = parseIntEnv("MAX_AGENTS_PER_OWNER", 10); err != nil {
		return c, err
	}
	if c.IPRate, err = parseIntEnv("IP_RATE", 600); err != nil {
		return c, err
	}
	if c.UploadBodyTimeout, err = parseTimeoutEnv("UPLOAD_BODY_TIMEOUT", time.Hour); err != nil {
		return c, err
	}
	if c.UnverifiedFileTTL, err = parseTimeoutEnv("UNVERIFIED_FILE_TTL", 24*time.Hour); err != nil {
		return c, err
	}
	if c.DefaultTTL, err = parseDurationEnv("DEFAULT_TTL", "3h"); err != nil {
		return c, err
	}
	if c.MaxTTL, err = parseDurationEnv("MAX_TTL", "24h"); err != nil {
		return c, err
	}
	if c.SendRate, err = parseIntEnv("SEND_RATE", 100); err != nil {
		return c, err
	}
	if c.UploadRate, err = parseIntEnv("UPLOAD_RATE", 200); err != nil {
		return c, err
	}
	c.ApplyDefaults()
	return c, nil
}

// ApplyDefaults fills the derived defaults; safe to call on hand-built
// configs (tests, demo).
func (c *Config) ApplyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.HTTPAddr == "" {
		if c.Domain != "" && !c.BehindProxy {
			c.HTTPAddr = ":443"
		} else {
			c.HTTPAddr = ":8080"
		}
	}
	if c.SMTPAddr == "" && c.Domain != "" {
		c.SMTPAddr = ":25"
	}
	if c.MaxFileSize == 0 {
		c.MaxFileSize = 5 << 30
	}
	if c.StorageQuota == 0 {
		c.StorageQuota = 20 << 30
	}
	if c.StorageQuotaUnverified == 0 {
		c.StorageQuotaUnverified = 200 << 20
	}
	if c.HumanRecipientsMax == 0 {
		c.HumanRecipientsMax = 3
	}
	if c.DefaultTTL == 0 {
		c.DefaultTTL = 3 * time.Hour
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = 24 * time.Hour
	}
	if c.SendRate == 0 {
		c.SendRate = 100
	}
	if c.UploadRate == 0 {
		c.UploadRate = 200
	}
	if c.Metrics == "" {
		c.Metrics = "localhost"
	}
	if c.ConnectSendRate == 0 {
		c.ConnectSendRate = 50
	}
	if c.ConnectBytesPerDay == 0 {
		c.ConnectBytesPerDay = 5 << 30
	}
}

// Instance returns the addressing domain ("local" when none configured).
func (c *Config) Instance() string {
	if c.Domain != "" {
		return c.Domain
	}
	return "local"
}

// BaseURL returns the advertised base URL, no trailing slash.
func (c *Config) BaseURL() string {
	if c.PublicURL != "" {
		return c.PublicURL
	}
	if c.Domain != "" {
		return "https://" + c.Domain
	}
	addr := c.HTTPAddr
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return "http://" + addr
}

// EmailEnabled reports whether this instance can do email at all.
func (c *Config) EmailEnabled() bool { return c.Domain != "" }

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseIntEnv(k string, def int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def, nil
	}
	// Accept "100" and legacy "100/day/agent" style.
	v = strings.SplitN(v, "/", 2)[0]
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func parseDurationEnv(k, def string) (time.Duration, error) {
	v := envOr(k, def)
	d, err := ParseTTL(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}

// parseTimeoutEnv is parseDurationEnv plus an explicit off switch ("0"/"off").
func parseTimeoutEnv(k string, def time.Duration) (time.Duration, error) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	switch v {
	case "":
		return def, nil
	case "0", "off":
		return -1, nil // disabled (0 would mean "apply the default")
	}
	d, err := ParseTTL(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}

// ParseDiskReserve resolves a DISK_RESERVE value — "10%" of the volume, an
// absolute size like "50GB", or "off"/"0" — into bytes (0 = disabled).
// total is the volume capacity, needed for the percentage form.
func ParseDiskReserve(s string, total int64) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "0", "off":
		return 0, nil
	}
	if pctStr, ok := strings.CutSuffix(s, "%"); ok {
		pct, err := strconv.ParseFloat(strings.TrimSpace(pctStr), 64)
		if err != nil || pct <= 0 || pct >= 100 {
			return 0, fmt.Errorf("bad DISK_RESERVE percentage %q", s)
		}
		return int64(float64(total) * pct / 100), nil
	}
	n, err := ParseSize(s)
	if err != nil {
		return 0, fmt.Errorf("DISK_RESERVE: %w", err)
	}
	return n, nil
}

// ParseTTL parses positive durations like "90m", "3h", "24h", "1d".
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	var d time.Duration
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		d = time.Duration(n * 24 * float64(time.Hour))
	} else {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

func parseSizeEnv(k, def string) (int64, error) {
	v := envOr(k, def)
	n, err := ParseSize(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

// ParseSize parses sizes like "500MB", "5GB", "1048576".
func ParseSize(s string) (int64, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "TB"):
		mult, s = 1<<40, strings.TrimSuffix(s, "TB")
	case strings.HasSuffix(s, "GB"):
		mult, s = 1<<30, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(n * float64(mult)), nil
}
