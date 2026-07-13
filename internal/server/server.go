// Package server implements the AgentTransfer server: HTTP API + MCP + share
// pages, inbound SMTP, the TTL janitor, and the long-poll hub — one process,
// one folder of state.
package server

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/shehryarsaroya/agenttransfer/internal/apphost"
	"github.com/shehryarsaroya/agenttransfer/internal/mail"
	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

//go:embed templates/*.html static/launch/*.webp static/launch/*.jpg
var templateFS embed.FS

// Server owns all runtime state.
type Server struct {
	cfg      Config
	st       *store.Store
	hub      *hub
	metrics  *metrics
	outbound *mail.Outbound
	tmpl     *template.Template
	// appRunner is the narrow Unix-socket client for dynamic OCI apps. It is
	// nil when the instance offers static hosting only.
	appRunner *apphost.Client

	// stats backs the public landing-page counter strip (GET /v1/stats).
	stats statsCache

	// burnMu guards single-flight downloads of burn-after-read links.
	burnMu  sync.Mutex
	burning map[string]bool

	// severed tracks tokens revoked while a download may be in flight;
	// streaming loops consult it between chunks and abort. The janitor
	// clears entries once their link is long past expiry.
	severMu sync.RWMutex
	severed map[string]bool

	// idemFlight collapses concurrent sends carrying the same
	// Idempotency-Key into one execution.
	idemMu     sync.Mutex
	idemFlight map[string]chan struct{}

	// uploadLocks serializes the quota-check+insert step per agent.
	uploadLocks sync.Map // agentID → *sync.Mutex

	signupLimiter *ipLimiter
	// unauthLimiter guards the public no-identity endpoints (/f/, /u/, index);
	// nil when IP_RATE is disabled.
	unauthLimiter *ipLimiter

	// allowPrivateWebhooks disables the SSRF address guard so tests can deliver
	// to a loopback sink. NEVER set in production.
	allowPrivateWebhooks bool

	// lastDiskLog throttles the disk-guard log line to one per minute.
	lastDiskLog atomic.Int64

	// connect is the mothership hosting side, set when CONNECT_DOMAIN is
	// configured; nil otherwise.
	connect *connectHost
	// client is the connect client side, set when CONNECT points at a host;
	// nil otherwise.
	client *connectClient

	// baseURL is the advertised origin. It flips once, live, when a connect
	// client registers and adopts its borrowed public URL, so it is atomic:
	// request handlers read it while the connect goroutine may set it.
	baseURL atomic.Pointer[string]
}

func (s *Server) uploadLock(agentID string) *sync.Mutex {
	mu, _ := s.uploadLocks.LoadOrStore(agentID, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// New opens the store and builds a Server. If no admin token was configured
// and none exists yet, the generated one is returned once via firstBootAdmin.
func New(cfg Config) (s *Server, firstBootAdmin string, err error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}
	st, firstBootAdmin, err := store.Open(cfg.DataDir, cfg.AdminToken)
	if err != nil {
		return nil, "", err
	}
	st.SetInstance(cfg.Instance())
	// The unprivileged public service owns build-context materialization. Make
	// APP_ROOT before the root runner starts so a DynamicUser deployment never
	// inherits a root:root 0700 directory it cannot write. The runner is ordered
	// after this service in the shipped units and root can still access it.
	if cfg.AppDomain != "" || cfg.AppRunnerSocket != "" {
		if err := os.MkdirAll(cfg.AppRoot, 0o700); err != nil {
			st.Close()
			return nil, "", fmt.Errorf("create APP_ROOT: %w", err)
		}
		// Build contexts are derived scratch copies, never durable state. A
		// process/host crash can bypass the normal per-deploy defer, so reclaim
		// stale contexts before accepting another deployment. Persistent app
		// data lives under the sibling data/ directory.
		if err := os.RemoveAll(filepath.Join(cfg.AppRoot, "contexts")); err != nil {
			st.Close()
			return nil, "", fmt.Errorf("clean stale app build contexts: %w", err)
		}
	}

	var out *mail.Outbound
	if cfg.Outbound != "" {
		out, err = mail.ParseOutbound(cfg.Outbound)
		if err != nil {
			st.Close()
			return nil, "", err
		}
	}
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		st.Close()
		return nil, "", err
	}
	srv := &Server{
		cfg:           cfg,
		st:            st,
		hub:           newHub(),
		metrics:       &metrics{},
		outbound:      out,
		tmpl:          tmpl,
		burning:       map[string]bool{},
		severed:       map[string]bool{},
		idemFlight:    map[string]chan struct{}{},
		signupLimiter: newIPLimiter(10, time.Hour),
	}
	if cfg.AppRunnerSocket != "" {
		srv.appRunner, err = apphost.NewClient(apphost.ClientConfig{
			SocketPath: cfg.AppRunnerSocket,
			AuthToken:  cfg.AppRunnerToken,
			Timeout:    20 * time.Minute,
		})
		if err != nil {
			st.Close()
			return nil, "", err
		}
	}
	if cfg.IPRate > 0 {
		srv.unauthLimiter = newIPLimiter(int(cfg.IPRate), time.Hour)
	}
	// Resolve the disk reserve against the volume that actually holds the
	// data. Unresolvable (odd platform) degrades to guard-off with a warning
	// rather than refusing to boot.
	if cfg.DiskReserve != "" {
		if _, total, err := store.VolumeStats(cfg.DataDir); err != nil {
			log.Printf("agenttransfer: disk guard disabled — cannot stat %s: %v", cfg.DataDir, err)
		} else {
			reserve, err := ParseDiskReserve(cfg.DiskReserve, total)
			if err != nil {
				st.Close()
				return nil, "", err
			}
			st.SetDiskReserve(reserve)
		}
	}
	srv.SetBaseURL(cfg.BaseURL())
	if cfg.ConnectDomain != "" {
		srv.connect = newConnectHost(srv)
	}
	return srv, firstBootAdmin, nil
}

// Store exposes the store (demo and tests).
func (s *Server) Store() *store.Store { return s.st }

// SetBaseURL overrides the advertised base URL (demo/tests bind random ports).
func (s *Server) SetBaseURL(u string) {
	v := strings.TrimRight(u, "/")
	s.baseURL.Store(&v)
}

// BaseURL returns the advertised base URL.
func (s *Server) BaseURL() string {
	if v := s.baseURL.Load(); v != nil {
		return *v
	}
	return ""
}

// Close releases the store.
func (s *Server) Close() error {
	if s.appRunner != nil {
		s.appRunner.Close()
	}
	return s.st.Close()
}

// Handler builds the full HTTP handler (REST + MCP + pages).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Agents & identity.
	mux.HandleFunc("POST /v1/agents", s.handleCreateAgent)
	mux.HandleFunc("POST /v1/agents/self/rotate_key", s.auth(s.handleRotateKey))
	mux.HandleFunc("POST /v1/agents/self/settings", s.auth(s.handleSettings))
	mux.HandleFunc("POST /v1/agents/self/owner", s.auth(s.handleSetOwner))
	mux.HandleFunc("POST /v1/agents/{id}/verify", s.handleAdminVerify)
	mux.HandleFunc("POST /v1/agents/{id}/limits", s.handleAdminLimits) // admin
	mux.HandleFunc("DELETE /v1/agents/self", s.auth(s.handleDeleteSelf))
	mux.HandleFunc("DELETE /v1/agents/{id}", s.handleDeleteAgent) // admin
	mux.HandleFunc("GET /v1/whoami", s.auth(s.handleWhoami))
	mux.HandleFunc("GET /v1/agents/{name}/pubkey", s.auth(s.handlePubkey)) // sealed-transfer key lookup
	mux.HandleFunc("PUT /v1/agents/self/card", s.auth(s.handleSetCard))
	mux.HandleFunc("GET /v1/agents/{name}/card", s.auth(s.handleGetCard))
	mux.HandleFunc("GET /v1/directory", s.auth(s.handleDirectory))          // opt-in agent discovery
	mux.HandleFunc("PUT /v1/agents/self/policy", s.auth(s.handleSetPolicy)) // recipient accept policy

	// Folder.
	mux.HandleFunc("POST /v1/files", s.auth(s.handleUpload))
	mux.HandleFunc("PUT /v1/files/{name...}", s.auth(s.handleUpload))
	mux.HandleFunc("GET /v1/files", s.auth(s.handleListFiles))
	mux.HandleFunc("DELETE /v1/files/{sha}", s.auth(s.handleDeleteFile))
	mux.HandleFunc("POST /v1/files/{sha}/keep", s.auth(s.handleKeepFile))
	mux.HandleFunc("GET /v1/files/{sha}/content", s.auth(s.handleFileContent))

	// Links.
	mux.HandleFunc("POST /v1/links", s.auth(s.handleCreateLink))
	mux.HandleFunc("GET /v1/links", s.auth(s.handleListLinks))
	mux.HandleFunc("DELETE /v1/links/{token}", s.auth(s.handleRevokeLink))

	// Messaging.
	mux.HandleFunc("POST /v1/send", s.auth(s.handleSend))
	mux.HandleFunc("GET /v1/inbox", s.auth(s.handleInbox))
	mux.HandleFunc("GET /v1/inbox/wait", s.auth(s.handleInboxWait))
	mux.HandleFunc("GET /v1/inbox/{id}", s.auth(s.handleGetMessage))
	mux.HandleFunc("POST /v1/inbox/{id}/read", s.auth(s.handleMarkRead))

	// Spaces (shared multi-agent coordination contexts).
	mux.HandleFunc("POST /v1/spaces", s.auth(s.handleCreateSpace))
	mux.HandleFunc("GET /v1/spaces", s.auth(s.handleListSpaces))
	mux.HandleFunc("GET /v1/spaces/{id}", s.auth(s.handleGetSpace))
	mux.HandleFunc("POST /v1/spaces/{id}/members", s.auth(s.handleAddSpaceMember))
	mux.HandleFunc("DELETE /v1/spaces/{id}/members/{name}", s.auth(s.handleRemoveSpaceMember))
	mux.HandleFunc("POST /v1/spaces/{id}/events", s.auth(s.handlePostSpaceEvent))
	mux.HandleFunc("GET /v1/spaces/{id}/events", s.auth(s.handleSpaceEvents))
	mux.HandleFunc("GET /v1/spaces/{id}/files/{sha}/content", s.auth(s.handleSpaceFileContent))

	// Upload requests (human → agent).
	mux.HandleFunc("POST /v1/requests", s.auth(s.handleCreateRequest))

	// Webhooks (push delivery).
	mux.HandleFunc("POST /v1/webhooks", s.auth(s.handleCreateWebhook))
	mux.HandleFunc("GET /v1/webhooks", s.auth(s.handleListWebhooks))
	mux.HandleFunc("DELETE /v1/webhooks/{id}", s.auth(s.handleDeleteWebhook))

	// Per-agent app hosting. Source archives are ordinary folder blobs;
	// deployment is a small authenticated JSON control operation.
	mux.HandleFunc("GET /v1/apps/self", s.auth(s.handleAppStatus))
	mux.HandleFunc("POST /v1/apps/self/deploy", s.auth(s.handleAppDeploy))
	mux.HandleFunc("POST /v1/apps/self/stop", s.auth(s.handleAppStop))
	mux.HandleFunc("DELETE /v1/apps/self", s.auth(s.handleAppDelete))
	mux.HandleFunc("GET /v1/apps/self/logs", s.auth(s.handleAppLogs))

	// Receipts.
	mux.HandleFunc("GET /v1/receipts", s.auth(s.handleReceipts))
	mux.HandleFunc("GET /v1/receipts/export", s.handleReceiptsExport) // admin

	// Admin observability: who holds the disk, and is the guard tripping.
	mux.HandleFunc("GET /v1/admin/storage", s.handleAdminStorage) // admin

	// Owner verification: GET shows the confirm page, POST consumes — a GET
	// with side effects would let mail scanners approve on the owner's behalf.
	mux.HandleFunc("GET /verify", s.handleVerifyOwner)
	mux.HandleFunc("POST /verify", s.handleVerifyOwnerConfirm)

	// Unsubscribe (human recipients): same GET-shows/POST-acts split.
	mux.HandleFunc("GET /unsubscribe", s.handleUnsubscribe)
	mux.HandleFunc("POST /unsubscribe", s.handleUnsubscribeConfirm)

	// Share + upload pages — public and identity-free, so they carry the
	// per-IP limiter (authenticated routes are governed by per-agent
	// counters instead; IP-limiting those would punish NAT'd fleets).
	mux.HandleFunc("GET /f/{token}", s.unauthLimited(s.handleShare))
	mux.HandleFunc("HEAD /f/{token}", s.unauthLimited(s.handleShare))
	mux.HandleFunc("GET /u/{token}", s.unauthLimited(s.handleUploadPage))
	mux.HandleFunc("POST /u/{token}", s.unauthLimited(s.handleUploadSubmit))

	// MCP.
	mux.HandleFunc("/mcp", s.handleMCP)

	// Meta.
	mux.HandleFunc("GET /.well-known/agenttransfer", s.handleWellKnown)
	mux.HandleFunc("GET /.well-known/agent-card.json", s.handleAgentCard) // A2A-style discovery descriptor
	mux.HandleFunc("GET /v1/stats", s.unauthLimited(s.handleStats))       // public aggregate counters (landing page strip)
	mux.HandleFunc("GET /llms.txt", s.unauthLimited(s.handleLLMs))        // llms.txt convention: agent-readable overview
	mux.HandleFunc("GET /robots.txt", s.unauthLimited(s.handleRobots))
	mux.HandleFunc("GET /sitemap.xml", s.unauthLimited(s.handleSitemap))
	mux.HandleFunc("GET /launch", s.unauthLimited(s.handleLaunch))
	mux.HandleFunc("GET /static/launch/{name}", s.handleLaunchAsset)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /{$}", s.unauthLimited(s.handleIndex))

	// Connect host endpoints (served on the apex domain).
	if s.connect != nil {
		mux.HandleFunc("POST "+connectRegisterPath, s.connect.handleRegister)
		mux.HandleFunc("GET "+connectTunnelPath, s.connect.handleTunnel)
		mux.HandleFunc("GET "+connectVerifyPath, s.connect.handleVerify)
		mux.HandleFunc("POST "+connectVerifyPath, s.connect.handleVerifyConfirm)
		mux.HandleFunc("POST /connect/admin/suspend", s.connect.handleSuspend) // admin
	}

	// Connect client surface (admin-gated).
	if s.cfg.Connect != "" {
		mux.HandleFunc("GET /v1/connect", s.handleConnectStatus)
		mux.HandleFunc("POST /v1/connect/verify", s.handleConnectVerify)
	}

	return s.withCommon(mux)
}

func (s *Server) withCommon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		// App hosts are a disjoint wildcard namespace and never fall through to
		// control-plane routes on the apex. Route them before installing the
		// short JSON control-plane deadline: hosted APIs may legitimately stream
		// large or slow JSON bodies under their own application policy.
		if slug, ok := s.appSlugFromHost(r.Host); ok {
			s.metrics.httpRequests.Add(1)
			s.handleAppHost(w, r, slug)
			return
		}
		// Connect host: requests to <name>.<connectDomain> are proxied down
		// that instance's tunnel rather than served locally.
		if s.connect != nil {
			if name, ok := s.connect.isConnectSubdomain(r.Host); ok {
				s.metrics.httpRequests.Add(1)
				s.connect.proxy(w, r, name)
				return
			}
		}
		// Person pages live at /@handle — "@" can't start a mux wildcard
		// segment, so the prefix is routed here, ahead of the mux.
		if r.Method == http.MethodGet {
			if handle, ok := strings.CutPrefix(r.URL.Path, "/@"); ok && handle != "" && !strings.Contains(handle, "/") {
				s.metrics.httpRequests.Add(1)
				s.unauthLimited(func(w http.ResponseWriter, r *http.Request) {
					s.handlePersonPage(w, r, handle)
				})(w, r)
				return
			}
		}
		// Small JSON control requests should not be able to park a connection
		// indefinitely one byte at a time. Raw file uploads have their own much
		// longer, size-appropriate deadline in the upload handler. App and
		// Connect proxy traffic returned above and is deliberately excluded.
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
			defer rc.SetReadDeadline(time.Time{})
		}
		s.metrics.httpRequests.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Run starts the HTTP(S) listener, the inbound SMTP listener, and the
// janitor, then blocks until ctx is canceled.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 3)

	// Connect client: created before any listener serves traffic (handlers
	// read s.client), started after they're up.
	if s.cfg.Connect != "" {
		s.client = newConnectClient(s)
	}

	httpSrv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: large downloads stream for a long time.
	}

	var tlsCfg *tls.Config
	if s.cfg.Domain != "" && !s.cfg.BehindProxy && s.cfg.HTTPAddr == ":443" {
		certmagic.DefaultACME.Agreed = true
		if s.cfg.ACMEEmail != "" {
			certmagic.DefaultACME.Email = s.cfg.ACMEEmail
		}
		magic := certmagic.NewDefault()
		// Bind an issuer to THIS config and manage + solve challenges through
		// it. certmagic.DefaultACME is only a template — its internal config is
		// nil, so calling DefaultACME.HTTPChallengeHandler directly nil-panics
		// on every ACME-shaped request to :80 (recovered per-connection by
		// net/http, but it breaks the HTTP-01 path and floods the log).
		acme := certmagic.NewACMEIssuer(magic, certmagic.DefaultACME)
		magic.Issuers = []certmagic.Issuer{acme}
		// Mint per-host certificates on demand for active apps and live Connect
		// tunnels. This avoids requiring DNS-01 credentials while still keeping
		// arbitrary wildcard names from exhausting ACME issuance limits.
		if s.connect != nil || s.cfg.AppDomain != "" {
			magic.OnDemand = &certmagic.OnDemandConfig{
				DecisionFunc: func(ctx context.Context, name string) error {
					if name == s.cfg.Domain {
						return nil
					}
					if s.managedAppHost(name) {
						return nil
					}
					// Only mint a cert for an instance with a LIVE tunnel —
					// merely-registered names (cheap, anonymous) must not be
					// able to burn the domain's Let's Encrypt issuance budget.
					if s.connect != nil {
						if sub, ok := s.connect.isConnectSubdomain(name); ok {
							if s.connect.online(sub) != nil {
								return nil
							}
						}
					}
					return fmt.Errorf("not a managed name: %s", name)
				},
			}
		}
		if err := magic.ManageSync(ctx, []string{s.cfg.Domain}); err != nil {
			return fmt.Errorf("acme: %w", err)
		}
		tlsCfg = magic.TLSConfig()
		tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)

		ln, err := tls.Listen("tcp", s.cfg.HTTPAddr, tlsCfg)
		if err != nil {
			return err
		}
		go func() { errCh <- httpSrv.Serve(ln) }()

		// Port 80: ACME HTTP challenges + redirect to HTTPS. Uses the bound
		// issuer (see above), not the DefaultACME template.
		challenge := acme.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.ToLower(strings.TrimSuffix(r.Host, "."))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host != s.cfg.Domain && !s.managedAppHost(host) {
				if s.connect == nil {
					host = s.cfg.Domain
				} else if sub, ok := s.connect.isConnectSubdomain(host); !ok || s.connect.online(sub) == nil {
					host = s.cfg.Domain
				}
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		}))
		redirectSrv := &http.Server{Addr: ":80", Handler: challenge, ReadHeaderTimeout: 10 * time.Second}
		go func() { errCh <- redirectSrv.ListenAndServe() }()
		defer redirectSrv.Close()
	} else {
		ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return err
		}
		log.Printf("agenttransfer: http on %s (%s)", ln.Addr(), s.BaseURL())
		go func() { errCh <- httpSrv.Serve(ln) }()
	}

	if s.cfg.SMTPAddr != "" && s.cfg.Domain != "" {
		smtpSrv := s.newSMTPServer(tlsCfg)
		log.Printf("agenttransfer: smtp on %s for %s", s.cfg.SMTPAddr, s.cfg.Domain)
		go func() { errCh <- smtpSrv.ListenAndServe() }()
		defer smtpSrv.Close()
	}

	go s.janitorLoop(ctx)
	go s.webhookWorker(ctx)

	// Connect host: reap dead registrations.
	if s.connect != nil {
		stop := make(chan struct{})
		defer close(stop)
		go s.connect.reapLoop(stop)
		log.Printf("agenttransfer: connect hosting for *.%s", s.cfg.ConnectDomain)
	}

	// Connect client: keep an outbound tunnel to the host so this instance is
	// reachable and email-served with no ports, DNS, or relay of its own.
	if s.client != nil {
		go s.client.run(ctx)
	}

	select {
	case <-ctx.Done():
		shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shctx)
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// ---- janitor ----

func (s *Server) janitorLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.JanitorOnce(); err != nil {
				log.Printf("janitor: %v", err)
			}
		}
	}
}

// JanitorOnce runs one janitor sweep: expire links, expire unclaimed files,
// GC orphan blobs, prune bookkeeping. Exported for tests and the demo.
func (s *Server) JanitorOnce() error {
	now := time.Now().Unix()
	links, err := s.st.ExpireLinks(now)
	if err != nil {
		return err
	}
	for _, l := range links {
		actor := s.agentEmailByID(l.AgentID)
		_, _ = s.st.AppendReceipt(actor, receipt.ActionExpired, l.SHA256, l.Size, "link:"+l.Token, "")
	}
	files, err := s.st.ExpireFiles(now)
	if err != nil {
		return err
	}
	for _, f := range files {
		actor := s.agentEmailByID(f.AgentID)
		_, _ = s.st.AppendReceipt(actor, receipt.ActionExpired, f.SHA256, f.Size, "file:"+f.Name, "")
	}
	if _, err := s.st.DeleteOrphanBlobs(); err != nil {
		return err
	}

	// Drop severed-token entries whose links are long past any possible
	// in-flight download, so the map can't grow forever.
	s.severMu.Lock()
	for token := range s.severed {
		l, err := s.st.GetLink(token)
		if err != nil || l.ExpiresAt < now-3600 {
			delete(s.severed, token)
		}
	}
	s.severMu.Unlock()

	// Reclaim deliveries wedged 'delivering' for >5 min (a lost terminal
	// write), and drop terminal delivery rows older than a day.
	_ = s.st.ReclaimStuckDeliveries(now - 300)
	_ = s.st.PruneWebhookDeliveries(now - 24*3600)

	// Release handles squatted by never-verified person signups (48 h): a
	// pending person grants nothing, but it does hold the handle — this
	// returns it to the pool.
	_, _ = s.st.SweepStalePendingPersons(48 * 3600)

	// Writable container data does not pass through PutBlob, so the runner
	// measures it directly. Stop an app that grows beyond its combined
	// release+data quota; its data is retained for the owner to inspect/purge.
	if s.appRunner != nil {
		if apps, err := s.st.AppsWithContainerHistory(); err == nil {
			for _, candidate := range apps {
				s.reconcileAppQuota(candidate.AgentID)
			}
		}
	}

	return s.st.Prune()
}

// reconcileAppQuota serializes janitor work with every user-triggered app
// mutation. A Docker build can outlive a janitor tick; acting on the stale app
// snapshot from AppsWithContainerHistory could otherwise stop the newly
// healthy runtime just before deploy commits it. Re-read SQLite only after
// acquiring the same lifecycle lock used by deploy/stop/reset/purge.
func (s *Server) reconcileAppQuota(agentID string) {
	appMu := s.uploadLock("app:" + agentID)
	appMu.Lock()
	defer appMu.Unlock()

	app, err := s.st.AppByAgentID(agentID)
	if err != nil || !app.EverContainer {
		return
	}
	if app.Status != store.AppStatusRunning || app.ActiveDeploymentID == "" {
		// Error/stopped apps are not publicly routed, but Docker may still be
		// running after a transient stop failure. Retry every sweep until every
		// managed runtime converges to stopped.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		stopErr := s.stopAllAppRuntimes(stopCtx, app)
		stopCancel()
		if stopErr != nil {
			log.Printf("apphost: stop inactive app %s runtimes: %v", app.ID, stopErr)
		}
		return
	}
	if app.Kind == store.AppKindStatic {
		// A transient cleanup failure during container→static switching must not
		// leave the old container writing/egressing forever. This is idempotent
		// and preserves persistent /data.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := s.appRunner.RemoveApp(cleanupCtx, app.ID)
		cleanupCancel()
		if cleanupErr != nil {
			log.Printf("apphost: reconcile static app %s runtimes: %v", app.ID, cleanupErr)
		}
	} else if app.RuntimeID != "" {
		reconcileCtx, reconcileCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, reconcileErr := s.appRunner.ReconcileApp(reconcileCtx, app.ID, app.RuntimeID)
		reconcileCancel()
		if reconcileErr != nil {
			log.Printf("apphost: reconcile container app %s runtime: %v", app.ID, reconcileErr)
		}
	}

	checkCtx, checkCancel := context.WithTimeout(context.Background(), 15*time.Second)
	var observed apphost.AppStatus
	if app.RuntimeID != "" {
		observed, err = s.appRunner.RuntimeStatus(checkCtx, app.RuntimeID)
	} else {
		observed, err = s.appRunner.Status(checkCtx, app.ID)
	}
	checkCancel()
	if err != nil {
		if appObservationMustFailClosed(err) {
			// A missing runtime or an authoritative data-scan failure cannot be
			// left publicly routed/unmetered. Other errors (runner restart, Docker
			// daemon bounce, request timeout) are retried next sweep so a transient
			// infrastructure blip does not take the whole hosted fleet offline.
			s.stopAppForSafety(app, fmt.Sprintf("runtime/storage inspection failed: %v", err))
		} else {
			log.Printf("apphost: defer app %s quota check after transient inspection failure: %v", app.ID, err)
		}
		return
	}
	if !observed.Running || observed.URL == "" {
		s.stopAppForSafety(app, "active runtime is no longer running or published")
		return
	}
	if observed.URL != app.Upstream {
		if err := s.st.RefreshAppRuntimeUpstream(app.AgentID, app.RuntimeID, observed.URL); err != nil {
			log.Printf("apphost: refresh app %s runtime endpoint: %v", app.ID, err)
			return
		}
	}
	usage, err := s.st.ActiveAppUsage(app.AgentID)
	if err != nil {
		s.stopAppForSafety(app, fmt.Sprintf("release storage inspection failed: %v", err))
		return
	}
	if usage.TotalBytes+observed.DataBytes <= s.cfg.AppStorageQuota {
		return
	}
	s.stopAppForSafety(app, fmt.Sprintf("storage usage %d exceeds quota %d",
		usage.TotalBytes+observed.DataBytes, s.cfg.AppStorageQuota))
}

func appObservationMustFailClosed(err error) bool {
	var apiErr *apphost.APIError
	return errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusUnprocessableEntity)
}

func (s *Server) stopAppForSafety(app store.App, reason string) {
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	stopErr := s.stopAllAppRuntimes(stopCtx, app)
	stopCancel()
	message := "app stopped: " + reason
	if stopErr != nil {
		message += fmt.Sprintf("; runtime stop will be retried: %v", stopErr)
	}
	_ = s.st.SetAppError(app.AgentID, app.ActiveDeploymentID, message)
	log.Printf("apphost: %s", message)
}

func (s *Server) agentEmailByID(id string) string {
	a, err := s.st.AgentByID(id)
	if err != nil {
		return "unknown"
	}
	return a.Email
}

// ---- long-poll hub ----

type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[chan struct{}]struct{}{}} }

func (h *hub) subscribe(agentID string) (ch chan struct{}, cancel func()) {
	ch = make(chan struct{}, 1)
	h.mu.Lock()
	if h.subs[agentID] == nil {
		h.subs[agentID] = map[chan struct{}]struct{}{}
	}
	h.subs[agentID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[agentID], ch)
		if len(h.subs[agentID]) == 0 {
			delete(h.subs, agentID)
		}
		h.mu.Unlock()
	}
}

func (h *hub) notify(agentID string) {
	h.mu.Lock()
	for ch := range h.subs[agentID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

// ---- revocation registry (sever in-flight downloads) ----

func (s *Server) sever(token string) {
	s.severMu.Lock()
	s.severed[token] = true
	s.severMu.Unlock()
}

func (s *Server) isSevered(token string) bool {
	s.severMu.RLock()
	defer s.severMu.RUnlock()
	return s.severed[token]
}

// ---- metrics ----

type metrics struct {
	httpRequests    atomic.Int64
	uploads         atomic.Int64
	downloads       atomic.Int64
	sends           atomic.Int64
	inboundMail     atomic.Int64
	diskFullRejects atomic.Int64
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	switch s.cfg.Metrics {
	case "off":
		http.NotFound(w, r)
		return
	case "admin":
		if !s.st.IsAdmin(bearer(r)) {
			http.Error(w, "admin token required", http.StatusForbidden)
			return
		}
	default: // localhost
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		// A loopback reverse proxy makes every public request appear local.
		// In BEHIND_PROXY mode, localhost policy therefore falls back to admin.
		if s.cfg.BehindProxy || ip == nil || !ip.IsLoopback() {
			if !s.st.IsAdmin(bearer(r)) {
				http.Error(w, "metrics are localhost-only (or use the admin token)", http.StatusForbidden)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE agenttransfer_http_requests_total counter\nagenttransfer_http_requests_total %d\n", s.metrics.httpRequests.Load())
	fmt.Fprintf(w, "# TYPE agenttransfer_uploads_total counter\nagenttransfer_uploads_total %d\n", s.metrics.uploads.Load())
	fmt.Fprintf(w, "# TYPE agenttransfer_downloads_total counter\nagenttransfer_downloads_total %d\n", s.metrics.downloads.Load())
	fmt.Fprintf(w, "# TYPE agenttransfer_sends_total counter\nagenttransfer_sends_total %d\n", s.metrics.sends.Load())
	fmt.Fprintf(w, "# TYPE agenttransfer_inbound_mail_total counter\nagenttransfer_inbound_mail_total %d\n", s.metrics.inboundMail.Load())
	fmt.Fprintf(w, "# TYPE agenttransfer_disk_full_rejects_total counter\nagenttransfer_disk_full_rejects_total %d\n", s.metrics.diskFullRejects.Load())
}

// ---- per-IP limiter ----

// ipKey canonicalizes a client IP for rate accounting: IPv4 keys per address,
// IPv6 per /64 — a v6 host effectively owns its whole /64, so keying full
// addresses would hand an attacker 2^64 free identities per prefix.
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip // unparseable: rate-limit the raw string as one bucket
	}
	if a.Is4() || a.Is4In6() {
		return a.Unmap().String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// Auto-ban: a key denied banStrikes times within one window is banned for
// banFor — a persistent hammerer stops costing handler work. In-memory only;
// a restart forgives.
const (
	banStrikes = 20
	banFor     = 15 * time.Minute
)

type ipLimiter struct {
	mu        sync.Mutex
	events    map[string][]time.Time
	strikes   map[string]int
	bans      map[string]time.Time
	max       int
	window    time.Duration
	nextSweep time.Time
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		events: map[string][]time.Time{}, strikes: map[string]int{},
		bans: map[string]time.Time{}, max: max, window: window,
	}
}

func (l *ipLimiter) allow(ip string) bool {
	key := ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-l.window)

	if until, banned := l.bans[key]; banned {
		if now.Before(until) {
			return false
		}
		delete(l.bans, key)
	}

	// Once per window, drop keys whose events have all aged out — without the
	// sweep a unique-IP flood (trivial over IPv6 even with /64 keying) grows
	// the maps forever.
	if now.After(l.nextSweep) {
		for k, evs := range l.events {
			live := 0
			for _, t := range evs {
				if t.After(cut) {
					evs[live] = t
					live++
				}
			}
			if live == 0 {
				delete(l.events, k)
			} else {
				l.events[k] = evs[:live]
			}
		}
		for k, until := range l.bans {
			if now.After(until) {
				delete(l.bans, k)
			}
		}
		clear(l.strikes) // strikes only accumulate within a window
		l.nextSweep = now.Add(l.window)
	}

	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.events[key] = kept
		l.strikes[key]++
		if l.strikes[key] >= banStrikes {
			l.bans[key] = now.Add(banFor)
			delete(l.strikes, key)
		}
		return false
	}
	l.events[key] = append(kept, now)
	return true
}

// unauthLimited guards a public (unauthenticated) endpoint with the per-IP
// limiter — flood control for the surfaces that have no agent identity to
// charge. Deliberately generous: it exists to stop abuse, not shape traffic.
// Authenticated routes are NOT wrapped; they're governed by per-agent
// counters, and IP-limiting them would punish NAT'd fleets.
func (s *Server) unauthLimited(next http.HandlerFunc) http.HandlerFunc {
	if s.unauthLimiter == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.unauthLimiter.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "600")
			http.Error(w, "rate limit exceeded — try again later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.BehindProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			// The LAST hop is the one our own proxy appended and the only one
			// an attacker can't supply; XFF[0] is client-controlled, and
			// trusting it would let every request claim a fresh IP.
			parts := strings.Split(xf, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
