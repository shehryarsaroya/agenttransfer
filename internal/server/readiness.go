package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

const appReadinessCacheTTL = 15 * time.Second

type appHostingReadiness struct {
	RunnerConfigured bool
	RunnerReady      bool
	WildcardDNSReady bool
	CheckedAt        time.Time
}

func (s *Server) advertisedAppHosting(ctx context.Context) (static, containers bool) {
	if s.cfg.AppDomain == "" {
		return false, false
	}
	status := s.appHostingStatus(ctx)
	static = status.WildcardDNSReady
	containers = static && status.RunnerReady && (s.cfg.AppDataQuotaEnforced || s.cfg.AllowUnenforcedAppData) &&
		(!s.cfg.OpenSignup || s.cfg.AllowPublicContainers)
	return static, containers
}

// appHostingStatus probes optional app infrastructure without coupling the
// core API's liveness to it. Results are briefly cached because discovery and
// load-balancer health endpoints are public and frequently polled.
func (s *Server) appHostingStatus(ctx context.Context) appHostingReadiness {
	if status, fresh := s.cachedAppHostingStatus(); fresh {
		return status
	}
	s.appProbeMu.Lock()
	defer s.appProbeMu.Unlock()
	if status, fresh := s.cachedAppHostingStatus(); fresh {
		return status
	}

	status := appHostingReadiness{RunnerConfigured: s.appRunner != nil, CheckedAt: time.Now()}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	runnerDone := make(chan bool, 1)
	go func() {
		runnerDone <- s.appRunner != nil && s.appRunner.ContainerReady(probeCtx) == nil
	}()
	dnsDone := make(chan bool, 1)
	go func() {
		if s.cfg.AppDomain == "" {
			dnsDone <- false
			return
		}
		serviceHost := s.cfg.Domain
		if parsed, err := url.Parse(s.BaseURL()); err == nil && parsed.Hostname() != "" {
			serviceHost = parsed.Hostname()
		}
		_, err := CheckWildcardDNS(probeCtx, s.cfg.AppDomain, serviceHost)
		dnsDone <- err == nil
	}()

	for i := 0; i < 2; i++ {
		select {
		case status.RunnerReady = <-runnerDone:
			runnerDone = nil
		case status.WildcardDNSReady = <-dnsDone:
			dnsDone = nil
		case <-probeCtx.Done():
			i = 2
		}
	}
	s.appReadyMu.Lock()
	s.appReady = status
	s.appReadyMu.Unlock()
	return status
}

func (s *Server) cachedAppHostingStatus() (appHostingReadiness, bool) {
	s.appReadyMu.Lock()
	defer s.appReadyMu.Unlock()
	status := s.appReady
	return status, !status.CheckedAt.IsZero() && time.Since(status.CheckedAt) < appReadinessCacheTTL
}

func (s *Server) markAppRunnerReady() {
	s.appReadyMu.Lock()
	s.appReady.RunnerConfigured = true
	s.appReady.RunnerReady = true
	s.appReady.CheckedAt = time.Now()
	s.appReadyMu.Unlock()
}

// CheckWildcardDNS verifies two unpredictable subdomains. This distinguishes
// an actual wildcard from a fixed readiness record that happens to resolve.
func CheckWildcardDNS(ctx context.Context, domain, serviceHost string) ([]string, error) {
	if serviceHost == "" {
		return nil, errors.New("service hostname is unavailable for wildcard comparison")
	}
	expectedIPs, err := net.DefaultResolver.LookupHost(ctx, serviceHost)
	if err != nil {
		return nil, fmt.Errorf("service hostname %s does not resolve: %w", serviceHost, err)
	}
	if len(expectedIPs) == 0 {
		return nil, fmt.Errorf("service hostname %s has no addresses", serviceHost)
	}
	expected := map[string]bool{}
	for _, raw := range expectedIPs {
		if ip := net.ParseIP(raw); ip != nil {
			expected[ip.String()] = true
		}
	}
	var all []string
	for i := 0; i < 2; i++ {
		var token [8]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, fmt.Errorf("generate wildcard probe: %w", err)
		}
		name := "at-" + hex.EncodeToString(token[:]) + "." + domain
		ips, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil || len(ips) == 0 {
			if err == nil {
				err = fmt.Errorf("no addresses")
			}
			return nil, fmt.Errorf("%s does not resolve: %w", name, err)
		}
		matchesService := false
		for _, raw := range ips {
			if ip := net.ParseIP(raw); ip != nil && expected[ip.String()] {
				matchesService = true
				break
			}
		}
		if !matchesService {
			return nil, fmt.Errorf("%s does not resolve to the service hostname %s", name, serviceHost)
		}
		all = append(all, ips...)
	}
	return all, nil
}

func readinessHeader(enabled, ready, checked bool) string {
	if !enabled {
		return "disabled"
	}
	if !checked {
		return "unknown"
	}
	if ready {
		return "ready"
	}
	return "unavailable"
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	status, checked := s.cachedAppHostingStatus()
	w.Header().Set("X-AgentTransfer-App-Runner", readinessHeader(s.appRunner != nil, status.RunnerReady, checked))
	w.Header().Set("X-AgentTransfer-App-Wildcard-DNS", readinessHeader(s.cfg.AppDomain != "", status.WildcardDNSReady, checked))
	w.Header().Set("Cache-Control", "no-store")
	// Core liveness remains independent of optional app-hosting infrastructure.
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	status := s.appHostingStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"app_hosting": map[string]any{
			"configured":      s.cfg.AppDomain != "",
			"runner_ready":    status.RunnerReady,
			"wildcard_dns":    status.WildcardDNSReady,
			"container_ready": status.RunnerReady && status.WildcardDNSReady,
		},
	})
}
