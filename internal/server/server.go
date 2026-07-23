// Package server exposes the JSON API.
//
// Auth (Phase 2): every /api/v1 route except login requires an authenticated
// principal, resolved from either an "Authorization: Bearer <token>" header
// (automation) or a session cookie (web UI). Write operations additionally
// require the admin role. There is no public registration — users are
// provisioned via the CLI.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/bfalcher/certguard/internal/auth"
	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/notify"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/store"
)

const sessionCookie = "certguard_session"

type ctxKey int

const userKey ctxKey = 0

type Server struct {
	cfg    config.Config
	store  *store.Store
	sender notify.Sender
	mux    *http.ServeMux
}

func New(cfg config.Config, st *store.Store, sender notify.Sender) *Server {
	s := &Server{cfg: cfg, store: st, sender: sender, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	// Public.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)

	// Authenticated (any role).
	s.mux.Handle("POST /api/v1/auth/logout", s.authed(s.handleLogout))
	s.mux.Handle("GET /api/v1/auth/whoami", s.authed(s.handleWhoami))
	s.mux.Handle("GET /api/v1/certs", s.authed(s.handleListCerts))

	// Per-user notification channels (any authenticated user manages their own).
	s.mux.Handle("GET /api/v1/channels", s.authed(s.handleListChannels))
	s.mux.Handle("POST /api/v1/channels", s.authed(s.handleCreateChannel))
	s.mux.Handle("DELETE /api/v1/channels/{id}", s.authed(s.handleDeleteChannel))
	s.mux.Handle("POST /api/v1/channels/{id}/test", s.authed(s.handleTestChannel))

	// Admin-only (writes).
	s.mux.Handle("POST /api/v1/scan", s.adminOnly(s.handleScan))
	s.mux.Handle("POST /api/v1/certs", s.adminOnly(s.handleCreateCert))
	s.mux.Handle("DELETE /api/v1/certs/{id}", s.adminOnly(s.handleDeleteCert))

	// Browser UI (static assets + pages).
	s.registerUI()
}

// --- auth middleware ---

// authed resolves the caller from a bearer token or session cookie and rejects
// unauthenticated requests with 401.
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := s.resolveUser(r)
		if user == nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userKey, user)
		next(w, r.WithContext(ctx))
	})
}

// adminOnly is authed plus a role check.
func (s *Server) adminOnly(next http.HandlerFunc) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if u := userFrom(r.Context()); u == nil || !u.IsAdmin() {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	})
}

func (s *Server) resolveUser(r *http.Request) *model.User {
	if tok := auth.BearerToken(r.Header.Get("Authorization")); tok != "" {
		if u, err := s.store.UserByTokenHash(auth.HashSecret(tok)); err == nil {
			return u
		}
		return nil
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if u, err := s.store.UserBySessionHash(auth.HashSecret(c.Value)); err == nil {
			return u
		}
	}
	return nil
}

func userFrom(ctx context.Context) *model.User {
	u, _ := ctx.Value(userKey).(*model.User)
	return u
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	user, err := s.store.GetUserByEmail(req.Email)
	if err != nil || !auth.CheckPassword(user.PasswordHash, req.Password) {
		// Same response whether the email is unknown or the password is wrong.
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	sid, err := auth.GenerateSession()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	expires := time.Now().UTC().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(user.ID, auth.HashSecret(sid), expires); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not persist session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = s.store.DeleteSession(auth.HashSecret(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": userFrom(r.Context())})
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	type item struct {
		Cert          *model.Cert `json:"cert"`
		DaysRemaining int         `json:"days_remaining"`
	}
	out := make([]item, 0, len(certs))
	for _, c := range certs {
		out = append(out, item{Cert: c, DaysRemaining: c.DaysRemaining(now)})
	}
	writeJSON(w, http.StatusOK, out)
}

type scanRequest struct {
	Target string `json:"target"` // "host", "host:port", or URL
	Name   string `json:"name"`
	// ServerName overrides the SNI hostname sent in the handshake. Useful when
	// scanning a bare IP whose server routes by hostname (reverse proxies):
	// dial the IP but present this name. Empty means use the dialed host.
	ServerName string `json:"server_name"`
	DryRun     bool   `json:"dry_run"` // scan but do not persist
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host, port, err := scanner.ParseTarget(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout+2*time.Second)
	defer cancel()

	res, err := scanner.Scan(ctx, host, port, scanner.Options{
		Timeout:    s.cfg.ScanTimeout,
		ServerName: req.ServerName,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{"scan": res})
		return
	}
	stored, err := s.store.UpsertScan(req.Name, res)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": res, "saved": stored})
}

type createCertRequest struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`       // "manual" (default) or "file"
	ExpiresAt string   `json:"expires_at"` // "YYYY-MM-DD" or RFC3339
	Notes     string   `json:"notes"`
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	SHA256    string   `json:"sha256"`
	NotBefore string   `json:"not_before"`
	KeyType   string   `json:"key_type"`
	DNSNames  []string `json:"dns_names"`
}

// handleCreateCert adds a manually-entered or client-side-parsed (dropped file)
// certificate. Endpoint certs come through /scan instead.
func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	var req createCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	expires, err := parseFlexDate(req.ExpiresAt)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expires_at must be YYYY-MM-DD or RFC3339")
		return
	}
	kind := model.Kind(req.Kind)
	if kind != model.KindFile && kind != model.KindManual {
		kind = model.KindManual
	}
	c := &model.Cert{
		Name: req.Name, Kind: kind, ExpiresAt: expires, Notes: req.Notes,
		Subject: req.Subject, Issuer: req.Issuer, SHA256: req.SHA256,
		KeyType: req.KeyType, DNSNames: req.DNSNames,
	}
	if nb, err := parseFlexDate(req.NotBefore); err == nil {
		c.NotBefore = nb
	}
	stored, err := s.store.AddCert(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.SoftDelete(id); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "cert not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- notification channels (scoped to the authenticated user) ---

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	chans, err := s.store.ListChannels(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]model.Channel, 0, len(chans))
	for _, c := range chans {
		out = append(out, c.Redacted())
	}
	writeJSON(w, http.StatusOK, out)
}

type createChannelRequest struct {
	Type       string `json:"type"`
	Target     string `json:"target"`
	Thresholds string `json:"thresholds"`
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var req createChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	typ := model.ChannelType(req.Type)
	if !model.ValidChannelType(typ) {
		writeErr(w, http.StatusBadRequest, "type must be email, slack, discord, or webhook")
		return
	}
	if req.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	ch, err := s.store.CreateChannel(u.ID, typ, req.Target, req.Thresholds)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ch.Redacted())
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteChannel(id, u.ID); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "channel not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleTestChannel sends a sample notification through one of the user's
// channels so they can confirm it is wired up correctly.
func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	ch, err := s.store.GetChannel(id)
	if err != nil || ch.UserID != u.ID {
		writeErr(w, http.StatusNotFound, "channel not found")
		return
	}
	if s.sender == nil {
		writeErr(w, http.StatusServiceUnavailable, "notifications are not enabled on this server")
		return
	}
	sample := &model.Cert{Name: "certguard-test.example.com", ExpiresAt: time.Now().UTC().AddDate(0, 0, 3)}
	msg := notify.BuildMessage(sample, 3, time.Now().UTC())
	msg.Subject = "[certguard] test notification"
	if err := s.sender.Send(ch, msg); err != nil {
		writeErr(w, http.StatusBadGateway, "send failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// parseFlexDate accepts either a date-only "YYYY-MM-DD" (interpreted as UTC
// midnight) or a full RFC3339 timestamp.
func parseFlexDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errBadDate
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, errBadDate
}

var errBadDate = &dateError{}

type dateError struct{}

func (*dateError) Error() string { return "unrecognized date format" }

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
