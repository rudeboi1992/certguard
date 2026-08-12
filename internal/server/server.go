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
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bfalcher/certguard/internal/auth"
	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/coverage"
	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/notify"
	"github.com/bfalcher/certguard/internal/rdap"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/secret"
	"github.com/bfalcher/certguard/internal/store"
	"github.com/bfalcher/certguard/internal/twofa"
)

const sessionCookie = "certguard_session"

type ctxKey int

const userKey ctxKey = 0

type Server struct {
	cfg          config.Config
	store        *store.Store
	sender       notify.Sender
	vault        *vault // envelope-encrypted secret vault (may be locked)
	mux          *http.ServeMux
	loginLimiter *rateLimiter   // slows credential guessing on auth endpoints
	rdap         *rdapCache     // short-lived memo of registry lookups
	ceremonies   *ceremonyStore // in-flight WebAuthn challenges
}

func New(cfg config.Config, st *store.Store, sender notify.Sender) *Server {
	s := &Server{cfg: cfg, store: st, sender: sender, mux: http.NewServeMux()}
	s.loginLimiter = newRateLimiter(10, 15*time.Minute) // 10 attempts / IP / 15 min
	s.vault = newVault(st, cfg.MasterKey, cfg.KeyFile)
	s.rdap = newRDAPCache(10 * time.Minute)
	s.ceremonies = newCeremonyStore()
	s.routes()
	return s
}

// VaultInfo is exposed for startup logging.
func (s *Server) VaultInfo() (enabled, unlocked, passphrase bool) { return s.vault.status() }

func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }

func (s *Server) routes() {
	// Public.
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	// Rate-limited by client IP to slow credential guessing.
	s.mux.HandleFunc("POST /api/v1/auth/login", s.limitAuth(s.handleLogin))
	// First-run: create the initial admin from the browser, but only while no
	// users exist. Once one does, setup locks and there is no public sign-up.
	s.mux.HandleFunc("GET /api/v1/setup/status", s.handleSetupStatus)
	s.mux.HandleFunc("POST /api/v1/setup", s.limitAuth(s.handleSetup))
	// Public CA download (served only when CERTGUARD_CA_FILE is set).
	s.mux.HandleFunc("GET /ca.crt", s.handleCACert)

	// Authenticated (any role).
	s.mux.Handle("POST /api/v1/auth/logout", s.authed(s.handleLogout))
	s.mux.Handle("GET /api/v1/auth/whoami", s.authed(s.handleWhoami))
	s.mux.Handle("GET /api/v1/version", s.authed(s.handleVersion))
	s.mux.Handle("GET /api/v1/certs", s.authed(s.handleListCerts))
	s.mux.Handle("GET /api/v1/calendar.ics", s.authed(s.handleCalendar))
	s.mux.Handle("GET /api/v1/certs/{id}/calendar.ics", s.authed(s.handleCalendarOne))

	// Per-user notification channels (any authenticated user manages their own).
	s.mux.Handle("GET /api/v1/channels", s.authed(s.handleListChannels))
	s.mux.Handle("POST /api/v1/channels", s.authed(s.handleCreateChannel))
	s.mux.Handle("DELETE /api/v1/channels/{id}", s.authed(s.handleDeleteChannel))
	s.mux.Handle("POST /api/v1/channels/{id}/test", s.authed(s.handleTestChannel))

	// User management (admin) — so accounts can be created without the CLI.
	s.mux.Handle("GET /api/v1/users", s.adminOnly(s.handleListUsers))
	s.mux.Handle("POST /api/v1/users", s.adminOnly(s.handleCreateUser))
	s.mux.Handle("DELETE /api/v1/users/{id}", s.adminOnly(s.handleDeleteUser))

	// Scheduler visibility.
	s.mux.Handle("GET /api/v1/scan/status", s.authed(s.handleScanStatus))
	s.mux.Handle("POST /api/v1/scan/all", s.adminOnly(s.handleScanAll))

	// Backup / recovery (admin): download the vault key and a DB snapshot.
	s.mux.Handle("GET /api/v1/backup/key", s.adminOnly(s.handleBackupKey))
	s.mux.Handle("GET /api/v1/backup/db", s.adminOnly(s.handleBackupDB))

	// Vault lock/unlock + passphrase (admin).
	s.mux.Handle("GET /api/v1/vault/status", s.authed(s.handleVaultStatus))
	s.mux.Handle("POST /api/v1/vault/unlock", s.adminOnly(s.handleVaultUnlock))
	s.mux.Handle("POST /api/v1/vault/lock", s.adminOnly(s.handleVaultLock))
	s.mux.Handle("POST /api/v1/vault/passphrase", s.adminOnly(s.handleVaultPassphrase))

	// Zero-knowledge keyring: the browser produces the wrapped key; the server
	// only stores/serves it. Reading it needs a login (to then unlock locally).
	s.mux.Handle("GET /api/v1/vault/keyring", s.authed(s.handleZKKeyringGet))
	s.mux.Handle("POST /api/v1/vault/keyring", s.adminOnly(s.handleZKKeyringSet))
	s.mux.Handle("DELETE /api/v1/vault/keyring", s.adminOnly(s.handleZKKeyringDelete))

	// Two-factor (TOTP) — each user manages their own.
	// Security keys (WebAuthn). Registration is for the signed-in account; the
	// login pair is public but rate-limited, because it re-checks the password
	// before issuing a challenge.
	s.mux.Handle("POST /api/v1/webauthn/register/begin", s.authed(s.handleWebAuthnRegisterBegin))
	s.mux.Handle("POST /api/v1/webauthn/register/finish", s.authed(s.handleWebAuthnRegisterFinish))
	s.mux.Handle("GET /api/v1/webauthn/credentials", s.authed(s.handleListCredentials))
	s.mux.Handle("DELETE /api/v1/webauthn/credentials/{id}", s.authed(s.handleDeleteCredential))
	// Usernameless passkey sign-in. Takes no address and returns the same
	// challenge whatever accounts exist, so it reveals nothing about who is
	// registered — the safe route for an instance exposed beyond a LAN.
	s.mux.HandleFunc("POST /api/v1/auth/passkey/begin", s.limitAuth(s.handlePasskeyBegin))
	s.mux.HandleFunc("POST /api/v1/auth/passkey/finish", s.limitAuth(s.handlePasskeyFinish))
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/begin", s.limitAuth(s.handleWebAuthnLoginBegin))
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/finish", s.limitAuth(s.handleWebAuthnLoginFinish))

	// Pairing a security key with the vault. Reads are for the signed-in owner
	// (the payload is useless without the physical key); changes are admin-only,
	// matching who may unlock the vault at all.
	s.mux.Handle("GET /api/v1/vault/wrappers/{cid}", s.authed(s.handleVaultWrapperGet))
	s.mux.Handle("PUT /api/v1/vault/wrappers/{cid}", s.adminOnly(s.handleVaultWrapperSet))
	s.mux.Handle("DELETE /api/v1/vault/wrappers/{cid}", s.adminOnly(s.handleVaultWrapperDelete))

	s.mux.Handle("POST /api/v1/2fa/setup", s.authed(s.handle2FASetup))
	s.mux.Handle("GET /api/v1/2fa/qr", s.authed(s.handle2FAQR))
	s.mux.Handle("POST /api/v1/2fa/enable", s.authed(s.handle2FAEnable))
	s.mux.Handle("POST /api/v1/2fa/disable", s.authed(s.handle2FADisable))

	// Admin-only (writes).
	s.mux.Handle("POST /api/v1/scan", s.adminOnly(s.handleScan))
	s.mux.Handle("POST /api/v1/certs", s.adminOnly(s.handleCreateCert))
	s.mux.Handle("POST /api/v1/certs/{id}/rescan", s.adminOnly(s.handleRescanCert))
	s.mux.Handle("POST /api/v1/certs/{id}/coverage", s.adminOnly(s.handleCoverage))
	s.mux.Handle("POST /api/v1/domains", s.adminOnly(s.handleTrackDomain))
	s.mux.Handle("POST /api/v1/domains/candidates", s.adminOnly(s.handleDomainCandidates))
	s.mux.Handle("PATCH /api/v1/certs/{id}", s.adminOnly(s.handleUpdateCert))
	s.mux.Handle("DELETE /api/v1/certs/{id}", s.adminOnly(s.handleDeleteCert))

	// Encrypted secret vault (admin). Reveal returns plaintext; set/clear write.
	s.mux.Handle("GET /api/v1/certs/{id}/secret", s.adminOnly(s.handleRevealSecret))
	s.mux.Handle("PUT /api/v1/certs/{id}/secret", s.adminOnly(s.handleSetSecret))

	// Activity log (any authenticated user may read it).
	s.mux.Handle("GET /api/v1/events", s.authed(s.handleListEvents))

	// Public status — unauthenticated, and served only when explicitly enabled
	// via CERTGUARD_STATUS_PUBLIC. Counts only; see handlePublicStatus.
	s.mux.HandleFunc("GET /api/v1/status/public", s.handlePublicStatus)

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
	Code     string `json:"code"` // TOTP code, when 2FA is enabled
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
	// Second factor, if the account has one. An account may hold a TOTP secret,
	// one or more security keys, or both; the client is told which so it can
	// offer the right thing rather than guess.
	keys, _ := s.store.CountCredentials(user.ID)
	if user.TOTPEnabled || keys > 0 {
		// A correct TOTP code satisfies the requirement outright. A security
		// key cannot be verified here — it needs a challenge — so the client is
		// sent to /auth/webauthn/begin instead.
		if !(user.TOTPEnabled && twofa.Validate(user.TOTPSecret, req.Code)) {
			var methods []string
			if user.TOTPEnabled {
				methods = append(methods, "totp")
			}
			if keys > 0 {
				methods = append(methods, "webauthn")
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":   "2fa_required",
				"methods": methods,
			})
			return
		}
	}
	if err := s.startSession(w, user); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// startSession creates a persisted session for user and sets the cookie.
func (s *Server) startSession(w http.ResponseWriter, user *model.User) error {
	sid, err := auth.GenerateSession()
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(user.ID, auth.HashSecret(sid), expires); err != nil {
		return err
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
	return nil
}

// handleSetupStatus reports whether the instance still needs its first account.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": n == 0})
}

// handleSetup creates the first admin account — only while none exists — and
// signs them in. Afterwards it is permanently locked (no public registration).
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, "setup already completed — ask an admin to add your account")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()) // e.g. password too short
		return
	}
	user, err := s.store.CreateUser(req.Email, hash, string(auth.RoleAdmin))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create account")
		return
	}
	if err := s.startSession(w, user); err != nil {
		writeErr(w, http.StatusInternalServerError, "account created but session failed; try signing in")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users) // PasswordHash is json:"-"
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	role := req.Role
	if role == "" {
		role = string(auth.RoleViewer)
	}
	if !auth.Role(role).Valid() {
		writeErr(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.store.CreateUser(req.Email, hash, role)
	if err != nil {
		writeErr(w, http.StatusConflict, "could not create user (email may already exist)")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if me := userFrom(r.Context()); me != nil && me.ID == id {
		writeErr(w, http.StatusBadRequest, "you can't delete your own account")
		return
	}
	if err := s.store.DeleteUser(id); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	enabled, unlocked, passphrase := s.vault.status()
	writeJSON(w, http.StatusOK, map[string]any{
		"user":             userFrom(r.Context()),
		"secrets_enabled":  enabled,
		"vault_unlocked":   unlocked,
		"vault_passphrase": passphrase,
		"zk_enabled":       s.vault.zkOn(),
		"ca_available":     s.cfg.CAFile != "" || s.cfg.CADownloadURL != "",
		"ca_url":           s.caURL(),
		// So the nav can offer the public status page only where it exists.
		"status_public": s.cfg.StatusPublic,
	})
}

// caURL is where the "Download CA certificate" button points: an external URL if
// one is configured (e.g. a bundled proxy serving it), else certguard's own
// /ca.crt (which serves CAFile).
func (s *Server) caURL() string {
	if s.cfg.CADownloadURL != "" {
		return s.cfg.CADownloadURL
	}
	return "/ca.crt"
}

// handleCACert serves the configured CA certificate for download, so users can
// install trust for an internal-CA HTTPS setup. Public (a root cert is not
// secret, and it's needed to bootstrap trust before the padlock is valid).
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if s.cfg.CAFile == "" {
		writeErr(w, http.StatusNotFound, "no CA certificate is configured")
		return
	}
	b, err := os.ReadFile(s.cfg.CAFile)
	if err != nil {
		writeErr(w, http.StatusNotFound, "CA certificate not available yet")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="certguard-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

type setSecretRequest struct {
	Value string `json:"value"`         // plaintext (non-ZK: server encrypts)
	Enc   string `json:"enc,omitempty"` // client ciphertext (ZK: stored verbatim)
	Hint  string `json:"hint,omitempty"`
}

// handleSetSecret stores (or clears) the secret for an entry. In zero-knowledge
// mode the body carries client-side ciphertext (enc + hint) which is stored as
// is; otherwise the server encrypts the plaintext value.
func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	if !s.vault.statusEnabled() {
		writeErr(w, http.StatusServiceUnavailable, "secret vault not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req setSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var storeErr error
	var hasSecret bool
	var hint string
	if s.vault.zkOn() {
		storeErr = s.store.SetSecret(id, req.Enc, req.Hint)
		hasSecret, hint = req.Enc != "", req.Hint
	} else {
		if !s.vault.isUnlocked() {
			writeErr(w, http.StatusLocked, "vault is locked — unlock it first")
			return
		}
		storeErr = s.storeSecret(id, req.Value)
		hasSecret, hint = req.Value != "", secret.Hint(req.Value)
	}
	if storeErr != nil {
		if storeErr == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "entry not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, storeErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"has_secret": hasSecret, "secret_hint": hint})
}

// storeSecret seals value (or clears when empty) and persists it.
func (s *Server) storeSecret(id int64, value string) error {
	if value == "" {
		return s.store.SetSecret(id, "", "")
	}
	enc, err := s.vault.seal(value)
	if err != nil {
		return err
	}
	return s.store.SetSecret(id, enc, secret.Hint(value))
}

// handleRevealSecret decrypts and returns the plaintext secret for an entry.
// Admin-only; this is the single path that ever emits plaintext.
func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request) {
	if !s.vault.statusEnabled() {
		writeErr(w, http.StatusServiceUnavailable, "secret vault not enabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.store.GetByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "entry not found")
		return
	}
	if c.SecretEnc == "" {
		writeErr(w, http.StatusNotFound, "no secret stored for this entry")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.vault.zkOn() {
		// Zero-knowledge: hand back the ciphertext; the browser decrypts it.
		writeJSON(w, http.StatusOK, map[string]string{"enc": c.SecretEnc})
		return
	}
	if !s.vault.isUnlocked() {
		writeErr(w, http.StatusLocked, "vault is locked — unlock it first")
		return
	}
	plain, err := s.vault.open(c.SecretEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"value": plain})
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
	// Notes is applied after the entry is stored. A scan writes the certificate
	// fields it discovered, so the note cannot ride along with it.
	Notes string `json:"notes"`
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
	stored = s.applyNotes(stored, req.Notes)
	s.recordEvent(r, store.EventAdded, stored, "endpoint")
	writeJSON(w, http.StatusOK, map[string]any{"scan": res, "saved": stored})
}

type createCertRequest struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`       // "manual" (default) or "file"
	Category  string   `json:"category"`   // certificate | api-key | subscription | ...
	ExpiresAt string   `json:"expires_at"` // "YYYY-MM-DD" or RFC3339
	Notes     string   `json:"notes"`
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	SHA256    string   `json:"sha256"`
	NotBefore string   `json:"not_before"`
	KeyType   string   `json:"key_type"`
	DNSNames  []string `json:"dns_names"`
	Secret    string   `json:"secret"` // optional; stored encrypted if the vault is enabled
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
		Name: req.Name, Kind: kind, Category: req.Category, ExpiresAt: expires, Notes: req.Notes,
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
	// Attach an optional secret (best-effort; the entry is already created). In
	// zero-knowledge mode the browser encrypts + stores it in a follow-up call.
	if req.Secret != "" && !s.vault.zkOn() && s.vault.isUnlocked() {
		if err := s.storeSecret(stored.ID, req.Secret); err == nil {
			stored, _ = s.store.GetByID(stored.ID)
		}
	}
	s.recordEvent(r, store.EventAdded, stored, string(stored.Kind))
	writeJSON(w, http.StatusCreated, stored)
}

type updateCertRequest struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Notes    string `json:"notes"`
}

// handleUpdateCert renames / re-labels an existing entry.
func (s *Server) handleUpdateCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req updateCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := s.store.UpdateEntry(id, req.Name, req.Category, req.Notes); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "entry not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _ := s.store.GetByID(id)
	s.recordEvent(r, store.EventUpdated, updated, "")
	writeJSON(w, http.StatusOK, updated)
}

// handleScanStatus reports the background scheduler's configuration so the UI
// can show whether auto-scan is on and how often it runs. The "last scan" time
// is derived client-side from the entries' last_scanned_at.
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":          s.cfg.SchedulerEnabled,
		"interval_seconds": int(s.cfg.CheckInterval / time.Second),
	})
}

// handleScanAll re-scans every auto-rescan endpoint on demand (the same work the
// scheduler does on its timer), refreshing expiry/trust for the whole inventory.
func (s *Server) handleScanAll(w http.ResponseWriter, r *http.Request) {
	eps, err := s.store.EndpointsForRescan()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	scanned, errs := 0, 0
	for _, c := range eps {
		if ctx.Err() != nil {
			break
		}
		res, err := scanner.Scan(ctx, c.Host, c.Port, scanner.Options{Timeout: s.cfg.ScanTimeout, ServerName: c.ServerName})
		if err != nil {
			errs++
			_ = s.store.TouchScanError(c.ID, err.Error())
			continue
		}
		if _, err := s.store.UpsertScan(c.Name, res); err != nil {
			errs++
			continue
		}
		scanned++
	}
	writeJSON(w, http.StatusOK, map[string]int{"total": len(eps), "scanned": scanned, "errors": errs})
}

// handleBackupKey streams the secret-vault master key as a download so an admin
// can keep a safe copy without shell access. Sensitive: admin-only, no-store.
func (s *Server) handleBackupKey(w http.ResponseWriter, r *http.Request) {
	if !s.vault.statusEnabled() {
		writeErr(w, http.StatusServiceUnavailable, "secret vault not enabled")
		return
	}
	if s.vault.zkOn() {
		writeErr(w, http.StatusConflict, "zero-knowledge mode — the server has no key; your recovery is the vault passphrase plus a database backup")
		return
	}
	if _, _, passphrase := s.vault.status(); passphrase {
		writeErr(w, http.StatusConflict, "vault is passphrase-protected — there is no key file to download; your recovery is your passphrase plus a database backup")
		return
	}
	material := s.cfg.MasterKey
	if material == "" {
		b, err := os.ReadFile(s.cfg.KeyFile)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "no key file to read")
			return
		}
		material = strings.TrimSpace(string(b))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="certguard.key"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, material)
}

// handleBackupDB streams a consistent snapshot of the SQLite database.
func (s *Server) handleBackupDB(w http.ResponseWriter, r *http.Request) {
	if s.store.Driver() != "sqlite" {
		writeErr(w, http.StatusBadRequest, "database download is only available for SQLite (use pg_dump for Postgres)")
		return
	}
	f, err := os.CreateTemp("", "certguard-backup-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp := f.Name()
	f.Close()
	_ = os.Remove(tmp) // VACUUM INTO requires the destination not to exist yet
	defer os.Remove(tmp)
	if err := s.store.BackupSQLite(tmp); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out, err := os.Open(tmp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer out.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="certguard-backup.db"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, out)
}

// handleRescanCert re-scans a single live endpoint on demand, refreshing its
// stored expiry and trust state. Only endpoint entries have somewhere to scan.
func (s *Server) handleRescanCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.store.GetByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "entry not found")
		return
	}
	// A domain registration refreshes by asking the registry, not by opening a
	// socket, but from the UI it is the same "refresh this now" button.
	if c.Kind == model.KindDomain {
		res, err := s.rdap.Lookup(r.Context(), c.Host, s.cfg.ScanTimeout, true)
		if err != nil {
			_ = s.store.TouchScanError(id, err.Error())
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		stored, err := s.store.UpsertDomain(c.Name, res)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, stored)
		return
	}
	if c.Kind != model.KindEndpoint || c.Host == "" {
		writeErr(w, http.StatusBadRequest, "only live endpoint entries can be rescanned")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout+2*time.Second)
	defer cancel()
	res, err := scanner.Scan(ctx, c.Host, c.Port, scanner.Options{
		Timeout:    s.cfg.ScanTimeout,
		ServerName: c.ServerName,
	})
	if err != nil {
		// Record the failed attempt so "last checked" and the error surface in UI.
		_ = s.store.TouchScanError(id, err.Error())
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	stored, err := s.store.UpsertScan(c.Name, res)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.store.GetByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "entry not found")
		return
	}
	if len(c.DNSNames) == 0 {
		writeErr(w, http.StatusBadRequest, "this entry does not list any covered names")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout+30*time.Second)
	defer cancel()
	out, port := coverage.Check(ctx, c, s.cfg.ScanTimeout)
	// Persisted so the dashboard can surface a broken name without the user
	// having to press this button again.
	_ = s.store.SaveCoverage(c.ID, out)
	writeJSON(w, http.StatusOK, map[string]any{"port": port, "names": out})
}

// handleTrackDomain looks a domain up over RDAP and stores it as a tracked
// registration. The input may be any hostname; it is reduced to the registrable
// domain, so scanning a subdomain and tracking its registration both work from
// whatever the user happens to have typed.
func (s *Server) handleTrackDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Name   string `json:"name"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Domain) == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	res, err := s.rdap.Lookup(r.Context(), req.Domain, s.cfg.ScanTimeout, false)
	if err != nil {
		// Not registered / no published expiry are ordinary answers about the
		// domain, not server faults, so they read as 4xx.
		if errors.Is(err, rdap.ErrNotRegistered) || errors.Is(err, rdap.ErrNoExpiry) {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	stored, err := s.store.UpsertDomain(req.Name, res)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored = s.applyNotes(stored, req.Notes)
	s.recordEvent(r, store.EventAdded, stored, "domain")
	writeJSON(w, http.StatusOK, map[string]any{"lookup": res, "saved": stored})
}

// domainCandidate is one registrable domain found behind a set of hostnames.
type domainCandidate struct {
	Domain    string     `json:"domain"`
	Tracked   bool       `json:"tracked"`
	Registrar string     `json:"registrar,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Status    []string   `json:"status,omitempty"`
	Error     string     `json:"error,omitempty"`
	// FromHosts is which of the submitted names reduced to this domain, so the
	// UI can explain where a suggestion came from.
	FromHosts []string `json:"from_hosts,omitempty"`
}

// handleDomainCandidates turns a pile of hostnames — a certificate's SANs, the
// hosts behind them — into the set of registrable domains they belong to, and
// looks each one up.
//
// The reduction has to happen here rather than in the browser because it needs
// the Public Suffix List: www.cpigaugescom.uniweldproducts.com belongs to
// uniweldproducts.com, and taking the last two labels would turn a .co.uk name
// into the unregistrable "co.uk".
func (s *Server) handleDomainCandidates(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Hosts) == 0 {
		writeErr(w, http.StatusBadRequest, "hosts is required")
		return
	}

	// Collapse to unique domains first — a certificate with a dozen SANs on one
	// domain must produce one lookup, not a dozen.
	order := []string{}
	from := map[string][]string{}
	for _, h := range req.Hosts {
		d, err := rdap.Registrable(h)
		if err != nil {
			continue
		}
		if _, seen := from[d]; !seen {
			order = append(order, d)
		}
		from[d] = append(from[d], h)
	}
	if len(order) > 40 {
		order = order[:40] // sanity bound on outbound lookups per request
	}

	existing, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tracked := map[string]bool{}
	for _, c := range existing {
		if c.Kind == model.KindDomain {
			tracked[strings.ToLower(c.Host)] = true
		}
	}

	out := make([]domainCandidate, len(order))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout+40*time.Second)
	defer cancel()

	for i, d := range order {
		out[i] = domainCandidate{Domain: d, FromHosts: from[d], Tracked: tracked[d]}
		if tracked[d] {
			continue // already known; no reason to hit the registry
		}
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := s.rdap.Lookup(ctx, d, s.cfg.ScanTimeout, false)
			if err != nil {
				out[i].Error = err.Error()
				return
			}
			exp := res.ExpiresAt
			out[i].ExpiresAt = &exp
			out[i].Registrar = res.Registrar
			out[i].Status = res.Status
		}(i, d)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

// handleCalendar returns all active entries as an .ics calendar file.
func (s *Server) handleCalendar(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeICS(w, "certguard.ics", certs)
}

// handleCalendarOne returns a single entry as an .ics file.
func (s *Server) handleCalendarOne(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := s.store.GetByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "entry not found")
		return
	}
	writeICS(w, "certguard-"+strconv.FormatInt(id, 10)+".ics", []*model.Cert{c})
}

func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	// Read it before it goes: the activity log denormalises the name, and after
	// a delete there is nothing left to look it up from.
	gone, _ := s.store.GetByID(id)
	if err := s.store.SoftDelete(id); err != nil {
		if err == store.ErrNotFound {
			writeErr(w, http.StatusNotFound, "cert not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.recordEvent(r, store.EventDeleted, gone, "")
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
