package server

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
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

	// AppDomain enables per-agent application hosting. An agent with slug
	// "alice" is served at https://alice.<AppDomain>. It may equal Domain
	// (alice@example.com -> alice.example.com), but must not equal
	// ConnectDomain because the two wildcard namespaces would be ambiguous.
	AppDomain string
	// AppStorageQuota is the logical source/release + persistent-data budget
	// for one human-verified agent. Container image layers are shared runtime
	// state and are reported globally rather than charged as exact bytes.
	AppStorageQuota int64
	// AppBundleSize caps the compressed source archive used for one deploy.
	AppBundleSize int64
	// AppRunnerSocket/Token point at the separate privileged container runner.
	// Static hosting works without a runner; container deploys do not.
	AppRunnerSocket string
	AppRunnerToken  string
	// AllowPublicContainers is an explicit high-risk opt-in for instances
	// where OPEN_SIGNUP lets any email-verified user obtain an identity.
	AllowPublicContainers bool
	// AllowUnenforcedAppData explicitly acknowledges that APP_STORAGE_QUOTA is
	// observed by the watchdog, not a kernel filesystem quota. Containers are
	// disabled by default until the operator provides isolation or accepts it.
	AllowUnenforcedAppData bool
	// AppDataQuotaEnforced declares that APP_DATA_ROOT has an operator-managed
	// filesystem/project quota at least as strict as APP_STORAGE_QUOTA.
	AppDataQuotaEnforced bool
	// AppBuildRoot is public-service-owned scratch space for materialized build
	// contexts. Persistent container data lives in the runner-only
	// APP_DATA_ROOT and must never be nested here.
	AppBuildRoot string
	// AppProxyBodySize and AppProxyConcurrency bound public traffic forwarded
	// into untrusted app runtimes. AppProxyBodyTimeout limits slow uploads;
	// AppProxyResponseHeaderTimeout limits an upstream that accepts a request
	// but never starts a response.
	AppProxyBodySize              int64
	AppProxyConcurrency           int
	AppProxyPerAppConcurrency     int
	AppProxyBodyTimeout           time.Duration
	AppProxyResponseHeaderTimeout time.Duration

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
	// MaxAgentsPerOwner caps how many agents one mailbox may human-verify.
	// Unproven nominations do not count; operator assertions bypass it. <0 disables.
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
	if strings.TrimSpace(os.Getenv("APP_ROOT")) != "" {
		return Config{}, fmt.Errorf("APP_ROOT is unsafe and no longer supported; set distinct APP_BUILD_ROOT and APP_DATA_ROOT")
	}
	c := Config{
		Domain:      strings.ToLower(strings.TrimSuffix(strings.TrimSpace(os.Getenv("DOMAIN")), ".")),
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

		AppDomain:              strings.ToLower(strings.TrimSuffix(strings.TrimSpace(os.Getenv("APP_DOMAIN")), ".")),
		AppRunnerSocket:        strings.TrimSpace(os.Getenv("APP_RUNNER_SOCKET")),
		AppRunnerToken:         strings.TrimSpace(os.Getenv("APP_RUNNER_TOKEN")),
		AppBuildRoot:           strings.TrimSpace(os.Getenv("APP_BUILD_ROOT")),
		AllowPublicContainers:  envBool("ALLOW_PUBLIC_CONTAINERS"),
		AllowUnenforcedAppData: envBool("ALLOW_UNENFORCED_APP_DATA"),
		AppDataQuotaEnforced:   envBool("APP_DATA_QUOTA_ENFORCED"),

		Connect:       strings.TrimRight(strings.TrimSpace(os.Getenv("CONNECT")), "/"),
		ConnectDomain: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(os.Getenv("CONNECT_DOMAIN")), ".")),

		DiskReserve: envOr("DISK_RESERVE", "10%"),
	}
	var err error
	if c.AppStorageQuota, err = parseSizeEnv("APP_STORAGE_QUOTA", "10GB"); err != nil {
		return c, err
	}
	if c.AppBundleSize, err = parseSizeEnv("APP_BUNDLE_SIZE", "500MB"); err != nil {
		return c, err
	}
	if c.AppProxyBodySize, err = parseSizeEnv("APP_PROXY_BODY_SIZE", "100MB"); err != nil {
		return c, err
	}
	if appProxyConcurrency, parseErr := parseIntEnv("APP_PROXY_CONCURRENCY", 128); parseErr != nil {
		return c, parseErr
	} else if appProxyConcurrency < 1 || appProxyConcurrency > 10000 {
		return c, fmt.Errorf("APP_PROXY_CONCURRENCY must be between 1 and 10000")
	} else {
		c.AppProxyConcurrency = int(appProxyConcurrency)
	}
	if perApp, parseErr := parseIntEnv("APP_PROXY_PER_APP_CONCURRENCY", 16); parseErr != nil {
		return c, parseErr
	} else if perApp < 1 || perApp > 10000 {
		return c, fmt.Errorf("APP_PROXY_PER_APP_CONCURRENCY must be between 1 and 10000")
	} else {
		c.AppProxyPerAppConcurrency = int(perApp)
	}
	if c.AppProxyBodyTimeout, err = parseDurationEnv("APP_PROXY_BODY_TIMEOUT", "15m"); err != nil {
		return c, err
	}
	if c.AppProxyResponseHeaderTimeout, err = parseDurationEnv("APP_PROXY_RESPONSE_HEADER_TIMEOUT", "30s"); err != nil {
		return c, err
	}
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
	if c.StorageQuotaUnverified, err = parseSizeEnv("STORAGE_QUOTA_UNVERIFIED", "400MB"); err != nil {
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
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

// ApplyDefaults fills the derived defaults; safe to call on hand-built
// configs (tests, demo).
func (c *Config) ApplyDefaults() {
	c.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Domain), "."))
	c.AppDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.AppDomain), "."))
	c.ConnectDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.ConnectDomain), "."))
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
		c.StorageQuotaUnverified = 400 << 20
	}
	if c.AppStorageQuota == 0 {
		c.AppStorageQuota = 10 << 30
	}
	if c.AppBundleSize == 0 {
		c.AppBundleSize = 500 << 20
	}
	if c.AppProxyBodySize == 0 {
		c.AppProxyBodySize = 100 << 20
	}
	if c.AppProxyConcurrency == 0 {
		c.AppProxyConcurrency = 128
	}
	if c.AppProxyPerAppConcurrency == 0 {
		c.AppProxyPerAppConcurrency = min(c.AppProxyConcurrency, 16)
	}
	if c.AppProxyBodyTimeout == 0 {
		c.AppProxyBodyTimeout = 15 * time.Minute
	}
	if c.AppProxyResponseHeaderTimeout == 0 {
		c.AppProxyResponseHeaderTimeout = 30 * time.Second
	}
	if c.AppBuildRoot == "" {
		c.AppBuildRoot = filepath.Join(c.DataDir, "app-builds")
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

// Validate rejects combinations that otherwise fail late or create an
// ambiguous wildcard routing namespace.
func (c *Config) Validate() error {
	if c.Domain != "" && !validDNSName(c.Domain) {
		return fmt.Errorf("DOMAIN must be a valid DNS name")
	}
	_, httpPort, err := net.SplitHostPort(c.HTTPAddr)
	if err != nil {
		return fmt.Errorf("HTTP_ADDR must be a TCP listen address: %w", err)
	}
	if c.Domain != "" && !c.BehindProxy && httpPort != "443" {
		return fmt.Errorf("HTTP_ADDR must use port 443 when DOMAIN enables built-in TLS")
	}
	if c.PublicURL != "" {
		u, err := parseBaseOrigin(c.PublicURL)
		if err != nil {
			return fmt.Errorf("PUBLIC_URL: %w", err)
		}
		if u.Scheme != "https" && !loopbackURLHost(u.Hostname()) {
			return fmt.Errorf("PUBLIC_URL must use https (plain HTTP is allowed only on loopback for development)")
		}
	}
	if c.AppDomain != "" {
		if !validDNSName(c.AppDomain) {
			return fmt.Errorf("APP_DOMAIN must be a valid DNS name")
		}
		if c.Domain == "" && !c.BehindProxy {
			return fmt.Errorf("APP_DOMAIN needs DOMAIN (built-in TLS) or BEHIND_PROXY=true")
		}
		if c.ConnectDomain != "" && strings.EqualFold(c.AppDomain, c.ConnectDomain) {
			return fmt.Errorf("APP_DOMAIN and CONNECT_DOMAIN must be different wildcard namespaces")
		}
	}
	if (c.AppRunnerSocket == "") != (c.AppRunnerToken == "") {
		return fmt.Errorf("APP_RUNNER_SOCKET and APP_RUNNER_TOKEN must be set together")
	}
	if c.AppProxyBodySize < 1 {
		return fmt.Errorf("APP_PROXY_BODY_SIZE must be positive")
	}
	if c.AppProxyConcurrency < 1 || c.AppProxyConcurrency > 10000 {
		return fmt.Errorf("APP_PROXY_CONCURRENCY must be between 1 and 10000")
	}
	if c.AppProxyPerAppConcurrency < 1 || c.AppProxyPerAppConcurrency > c.AppProxyConcurrency {
		return fmt.Errorf("APP_PROXY_PER_APP_CONCURRENCY must be between 1 and APP_PROXY_CONCURRENCY")
	}
	if c.AppProxyBodyTimeout <= 0 || c.AppProxyResponseHeaderTimeout <= 0 {
		return fmt.Errorf("app proxy timeouts must be positive")
	}
	if c.Connect != "" {
		u, err := parseBaseOrigin(c.Connect)
		if err != nil {
			return fmt.Errorf("CONNECT: %w", err)
		}
		if u.Scheme != "https" && !loopbackURLHost(u.Hostname()) {
			return fmt.Errorf("CONNECT must use https:// (plain HTTP is allowed only on loopback for development)")
		}
	}
	if c.ConnectDomain != "" && !sameOrSubdomain(c.ConnectDomain, c.Domain) {
		return fmt.Errorf("CONNECT_DOMAIN must be DOMAIN or one of its subdomains")
	}
	if c.DefaultTTL > c.MaxTTL {
		return fmt.Errorf("DEFAULT_TTL must be <= MAX_TTL")
	}
	return nil
}

func sameOrSubdomain(name, parent string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	parent = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parent), "."))
	return parent != "" && (name == parent || strings.HasSuffix(name, "."+parent))
}

// parseBaseOrigin accepts only an absolute HTTP(S) origin. Control-plane base
// URLs are concatenated with fixed paths and used for trust decisions, so
// credentials, paths, queries, and fragments must never be smuggled into one.
func parseBaseOrigin(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, errors.New("must be a non-empty URL without surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("must be an absolute http(s) origin")
	}
	if u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("must not contain credentials, a path, query, or fragment")
	}
	return u, nil
}

func loopbackURLHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) builtInTLS() bool {
	if c.Domain == "" || c.BehindProxy {
		return false
	}
	_, port, err := net.SplitHostPort(c.HTTPAddr)
	return err == nil && port == "443"
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
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
		if err != nil || math.IsNaN(pct) || math.IsInf(pct, 0) || pct <= 0 || pct >= 100 {
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
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
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
	bytes := n * float64(mult)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 ||
		math.IsNaN(bytes) || math.IsInf(bytes, 0) || bytes >= math.Ldexp(1, 63) {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(bytes), nil
}
