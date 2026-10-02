package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/shehryarsaroya/agenttransfer/internal/receipt"
	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// downloadURLTTL bounds presigned download URLs. Validity is checked when a
// download starts, so a long transfer keeps going after the URL expires; a
// short TTL only limits how long a leaked URL stays useful.
func (s *Server) downloadURLTTL() time.Duration { return 15 * time.Minute }

// burnURLTTL is the window to start a burn-after-read download in bucket mode.
const burnURLTTL = 2 * time.Minute

// redirectToObject answers with a 302 to a presigned bucket URL. X-Sha256
// rides on the redirect so clients can verify the bytes they then receive.
func (s *Server) redirectToObject(w http.ResponseWriter, r *http.Request, sha, name, mime string, ttl time.Duration) bool {
	u, err := s.st.BlobURL(sha, name, mime, ttl)
	if err != nil {
		http.Error(w, "blob missing", http.StatusInternalServerError)
		return false
	}
	w.Header().Set("X-Sha256", sha)
	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	http.Redirect(w, r, u, http.StatusFound)
	return true
}

// streamNormalRemote is streamNormal for bucket mode: the bytes go straight
// from object storage. A redirect counts as the download — the server can no
// longer observe completion — so audit receipts record a started download.
func (s *Server) streamNormalRemote(w http.ResponseWriter, r *http.Request, l store.Link) {
	if !s.redirectToObject(w, r, l.SHA256, l.Name, l.MIME, s.downloadURLTTL()) {
		return
	}
	_ = s.st.CountDownload(l.Token)
	s.metrics.downloads.Add(1)
	s.appendReceipt(s.agentEmailByID(l.AgentID), receipt.ActionDownloaded, l.SHA256, l.Size, "link:"+l.Token, "")
}

// streamBurnRemote burns the link before handing out a short-lived URL: in
// bucket mode a single-use link is consumed when its download starts.
func (s *Server) streamBurnRemote(w http.ResponseWriter, r *http.Request, l store.Link) {
	if _, err := s.st.BurnLink(l.Token); err != nil {
		l2, _ := s.st.GetLink(l.Token)
		s.goneLink(w, l2)
		return
	}
	if !s.redirectToObject(w, r, l.SHA256, l.Name, l.MIME, burnURLTTL) {
		return
	}
	_ = s.st.CountDownload(l.Token)
	s.metrics.downloads.Add(1)
	actor := s.agentEmailByID(l.AgentID)
	s.appendReceipt(actor, receipt.ActionDownloaded, l.SHA256, l.Size, "link:"+l.Token, "")
	s.appendReceipt(actor, receipt.ActionBurned, l.SHA256, l.Size, "link:"+l.Token, "")
}

// linkNeedsAgent reports whether a share link may be downloaded only with an
// agent credential: on a PUBLIC_LINKS=verified instance, links owned by an
// unverified folder never serve anonymous browsers.
func (s *Server) linkNeedsAgent(l store.Link) bool {
	if s.cfg.PublicLinks != "verified" {
		return false
	}
	owner, err := s.st.AgentByID(l.AgentID)
	return err != nil || !owner.OwnerVerified
}

// requestAgent resolves the request's bearer credential (API key or OAuth
// access token) to an agent, if any.
func (s *Server) requestAgent(r *http.Request) (store.Agent, bool) {
	tok := bearer(r)
	if tok == "" {
		return store.Agent{}, false
	}
	a, err := s.agentForToken(tok)
	return a, err == nil
}

// agentForToken resolves an API key (at_live_…) or an OAuth access token
// (at_oat_…) to the agent it acts as.
func (s *Server) agentForToken(tok string) (store.Agent, error) {
	if strings.HasPrefix(tok, "at_oat_") {
		t, err := s.st.OAuthTokenByAccess(tok)
		if err != nil {
			return store.Agent{}, err
		}
		a, err := s.st.AgentByID(t.AgentID)
		if err != nil {
			return store.Agent{}, err
		}
		s.st.TouchGrant(a.ID)
		return a, nil
	}
	a, err := s.st.AgentByKey(tok)
	if err != nil {
		return store.Agent{}, err
	}
	if a.IsDrive() {
		return store.Agent{}, store.ErrNotFound // unreachable: drives have no key
	}
	return a, nil
}
