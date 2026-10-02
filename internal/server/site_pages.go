package server

import (
	"embed"
	"fmt"
	"net/http"
	"path"
	"strings"
)

//go:embed static/site/*
var siteFS embed.FS

// cors allows browser-based MCP clients to reach the OAuth endpoints. A nil
// handler answers preflights only.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions || next == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleOpenAIChallenge(w http.ResponseWriter, r *http.Request) {
	if s.cfg.OpenAIAppsChallenge == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(s.cfg.OpenAIAppsChallenge))
}

func (s *Server) handleSiteAsset(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name"))
	data, err := siteFS.ReadFile("static/site/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".png"):
		w.Header().Set("Content-Type", "image/png")
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	s.render(w, "docs.html", map[string]any{
		"Title": "Docs", "Description": "Connect ChatGPT, Claude, Muse and coding agents to one shared drive, and move files between agents.",
		"MCP": s.mcpResource(), "MaxFile": roundSize(s.cfg.MaxFileSize),
		"Quota": roundSize(s.cfg.StorageQuota), "QuotaAnon": roundSize(s.cfg.StorageQuotaUnverified),
		"Remote": s.st.Remote(),
	})
}

func (s *Server) handleLegal(w http.ResponseWriter, r *http.Request) {
	page := strings.TrimPrefix(r.URL.Path, "/")
	titles := map[string]string{"privacy": "Privacy policy", "terms": "Terms of service", "support": "Support"}
	operator := s.cfg.OperatorName
	if operator == "" {
		operator = "the operator of " + s.st.Instance()
	}
	contact := s.cfg.SupportEmail
	s.render(w, page+".html", map[string]any{
		"Title": titles[page], "Operator": operator, "Contact": contact, "Updated": "October 2, 2026",
		"Quota": roundSize(s.cfg.StorageQuota), "QuotaAnon": roundSize(s.cfg.StorageQuotaUnverified),
		"Remote": s.st.Remote(),
	})
}

// roundSize renders a configured limit for people: "20 GB", "400 MB".
func roundSize(n int64) string {
	const mb, gb = int64(1) << 20, int64(1) << 30
	switch {
	case n >= gb && n%gb == 0:
		return fmt.Sprintf("%d GB", n/gb)
	case n >= gb:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%d MB", (n+mb/2)/mb)
	default:
		return fmt.Sprintf("%d KB", (n+512)/1024)
	}
}
