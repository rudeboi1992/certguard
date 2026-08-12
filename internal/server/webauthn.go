package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/bfalcher/certguard/internal/auth"
	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/store"
)

// ceremonyCookie carries the handle to an in-flight WebAuthn ceremony. The
// challenge itself stays on the server; the browser only ever holds an opaque
// lookup token.
const ceremonyCookie = "certguard_ceremony"

// ceremonyTTL bounds how long a begun ceremony may sit unfinished. Long enough
// to find a key in a drawer, short enough that an abandoned challenge does not
// linger.
const ceremonyTTL = 5 * time.Minute

// ceremony is one in-flight registration or login.
type ceremony struct {
	session webauthn.SessionData
	userID  int64
	expires time.Time
}

// ceremonyStore holds in-flight ceremonies in memory. Deliberately not in the
// database: a challenge is single-use, expires in minutes, and losing them all
// on restart is correct behaviour rather than data loss. This does mean a
// ceremony cannot span two processes, which is fine — certguard is one binary.
type ceremonyStore struct {
	mu sync.Mutex
	m  map[string]ceremony
}

func newCeremonyStore() *ceremonyStore {
	return &ceremonyStore{m: make(map[string]ceremony)}
}

func (c *ceremonyStore) put(token string, cer ceremony) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Opportunistic sweep; the map only ever holds live ceremonies.
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[token] = cer
}

// take returns a ceremony and removes it: a challenge is single-use, so even a
// failed attempt consumes it and the browser must begin again.
func (c *ceremonyStore) take(token string) (ceremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cer, ok := c.m[token]
	delete(c.m, token)
	if !ok || time.Now().After(cer.expires) {
		return ceremony{}, false
	}
	return cer, true
}

// webAuthnUser adapts a certguard user to the library's User interface.
type webAuthnUser struct {
	user  *model.User
	creds []webauthn.Credential
}

// WebAuthnID is the user handle. The numeric ID is stable, which is what
// matters here — a handle that changed would orphan every registered key.
func (u *webAuthnUser) WebAuthnID() []byte { return []byte(strconv.FormatInt(u.user.ID, 10)) }

func (u *webAuthnUser) WebAuthnName() string                       { return u.user.Email }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.user.Email }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webAuthnUserFor loads a user together with their registered keys.
func (s *Server) webAuthnUserFor(u *model.User) (*webAuthnUser, error) {
	stored, err := s.store.CredentialsForUser(u.ID)
	if err != nil {
		return nil, err
	}
	wu := &webAuthnUser{user: u}
	for _, c := range stored {
		id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
		if err != nil {
			continue
		}
		pk, err := base64.RawURLEncoding.DecodeString(c.PublicKey)
		if err != nil {
			continue
		}
		cred := webauthn.Credential{
			ID:        id,
			PublicKey: pk,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{SignCount: c.SignCount},
		}
		if c.Transports != "" {
			for _, t := range strings.Split(c.Transports, ",") {
				cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
			}
		}
		wu.creds = append(wu.creds, cred)
	}
	return wu, nil
}

// rpConfig resolves the Relying Party identity for this request.
//
// Credentials are bound to the RP ID, so this value is load-bearing: change it
// and every registered key stops working. It comes from configuration when set,
// otherwise from the Host header, which is what a self-hoster reaching the
// instance by name expects.
func (s *Server) rpConfig(r *http.Request) (id string, origins []string, err error) {
	host := r.Host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}
	id = s.cfg.RPID
	if id == "" {
		id = host
	}
	// The spec requires a domain. An IP address is not one, and browsers reject
	// it outright — better to say so plainly than to let the browser throw a
	// SecurityError the operator has to decode.
	if ip := net.ParseIP(strings.Trim(id, "[]")); ip != nil {
		return "", nil, fmt.Errorf(
			"security keys need a domain name: this instance was reached at %q, and WebAuthn does not permit an IP address as a relying party ID. Give certguard a hostname (e.g. certguard.example.local) and reach it by that name", id)
	}
	origins = s.cfg.RPOrigins
	if len(origins) == 0 {
		scheme := "https"
		// A plain-HTTP origin is only a secure context on localhost, which is
		// exactly the case worth supporting for local development.
		if r.TLS == nil {
			scheme = "http"
		}
		origins = []string{scheme + "://" + r.Host}
	}
	return id, origins, nil
}

func (s *Server) webAuthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	id, origins, err := s.rpConfig(r)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          id,
		RPDisplayName: "certguard",
		RPOrigins:     origins,
	})
}

// setCeremony stores an in-flight ceremony and hands the browser its handle.
func (s *Server) setCeremony(w http.ResponseWriter, sess *webauthn.SessionData, userID int64) error {
	token, err := auth.GenerateSession()
	if err != nil {
		return err
	}
	s.ceremonies.put(token, ceremony{session: *sess, userID: userID, expires: time.Now().Add(ceremonyTTL)})
	http.SetCookie(w, &http.Cookie{
		Name:     ceremonyCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ceremonyTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request) (ceremony, bool) {
	ck, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return ceremony{}, false
	}
	// Clear it either way: a consumed or expired handle should not linger.
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	return s.ceremonies.take(ck.Value)
}

// --- registration -----------------------------------------------------------

// handleWebAuthnRegisterBegin starts adding a security key to the signed-in
// account.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.webAuthnUserFor(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load credentials")
		return
	}
	// Exclude what is already registered so the same key cannot be added twice.
	var exclude []protocol.CredentialDescriptor
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, sess, err := wa.BeginRegistration(wu,
		webauthn.WithExclusions(exclude),
		// Both preferred rather than required, because both are asking for a
		// capability the key may not have. A resident key lets this act as a
		// passkey; user verification is what makes a passwordless sign-in
		// two-factor rather than one. A key that can do neither is still a
		// perfectly good second factor next to the password — it just will not
		// be offered the passwordless path, which is enforced at login by
		// demanding verification there.
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not begin registration: "+err.Error())
		return
	}
	if err := s.setCeremony(w, sess, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start ceremony")
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// handleWebAuthnRegisterFinish completes registration and stores the key.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	cer, ok := s.takeCeremony(w, r)
	if !ok || cer.userID != u.ID {
		writeErr(w, http.StatusBadRequest, "no registration in progress — start again")
		return
	}
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.webAuthnUserFor(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load credentials")
		return
	}
	// The name rides along as a query parameter so the credential JSON the
	// browser produces can be forwarded to the library untouched.
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Security key"
	}
	if len(name) > 60 {
		name = name[:60]
	}

	cred, err := wa.FinishRegistration(wu, cer.session, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "registration failed: "+protocolErr(err))
		return
	}
	var transports []string
	for _, t := range cred.Transport {
		if t != "" {
			transports = append(transports, string(t))
		}
	}
	stored := &model.WebAuthnCredential{
		UserID:         u.ID,
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      base64.RawURLEncoding.EncodeToString(cred.PublicKey),
		AAGUID:         base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID),
		SignCount:      cred.Authenticator.SignCount,
		Transports:     strings.Join(transports, ","),
		Name:           name,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}
	if _, err := s.store.AddCredential(stored); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save credential")
		return
	}
	s.recordAccountEvent(store.EventKeyAdded, u.Email, u.Email, "registered security key "+strconv.Quote(name))
	writeJSON(w, http.StatusCreated, stored)
}

// --- login ------------------------------------------------------------------

// handleWebAuthnLoginBegin issues a challenge for signing in with a key.
//
// It serves two flows. With a password, the key is a second factor and the
// password has already been proved. Without one, the key is the ONLY factor —
// so user verification is demanded, which makes the authenticator require a PIN
// or biometric. That keeps the passwordless path genuinely two-factor
// (something you have plus something you know or are) rather than reducing
// sign-in to whoever is holding the key.
//
// A key with no PIN or biometric simply fails the ceremony, and the page falls
// back to the password. That is the correct outcome: such a key is one factor,
// and one factor is not enough on its own.
func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	user, err := s.store.GetUserByEmail(req.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	passwordless := req.Password == ""
	if !passwordless && !auth.CheckPassword(user.PasswordHash, req.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.webAuthnUserFor(user)
	if err != nil || len(wu.creds) == 0 {
		writeErr(w, http.StatusBadRequest, "no security key registered for this account")
		return
	}
	var opts []webauthn.LoginOption
	if passwordless {
		opts = append(opts, webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	assertion, sess, err := wa.BeginLogin(wu, opts...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not begin login: "+err.Error())
		return
	}
	// The requirement is carried in the stored session, so FinishLogin enforces
	// it server-side. A client that edits the options it was handed cannot
	// downgrade the check.
	if err := s.setCeremony(w, sess, user.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start ceremony")
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// --- usernameless passkey login ---------------------------------------------

// handlePasskeyBegin issues a challenge for signing in with a passkey when the
// server does not know, and is not told, who is signing in.
//
// This is the enumeration-safe way to offer passkeys. The response is
// byte-identical no matter which accounts exist — no address is submitted, no
// credential list is returned, and nothing is looked up. An instance exposed to
// the internet therefore leaks nothing about its users through this route,
// which is why it is preferred over asking "does this address have a key".
//
// The authenticator picks the credential and reports the user handle in its
// response, so the account is discovered at the finish step. Verification is
// required because the passkey is the only factor.
func (s *Server) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	assertion, sess, err := wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not begin login: "+err.Error())
		return
	}
	// userID 0: nobody is claimed yet. The finish step resolves it from the
	// handle the authenticator returns.
	if err := s.setCeremony(w, sess, 0); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start ceremony")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, assertion)
}

// discoverableUser resolves the account an authenticator claims to be. The
// handle is the user ID that WebAuthnID produced at registration.
func (s *Server) discoverableUser(rawID, userHandle []byte) (webauthn.User, error) {
	id, err := strconv.ParseInt(string(userHandle), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unrecognised user handle")
	}
	user, err := s.store.GetUserByID(id)
	if err != nil {
		return nil, fmt.Errorf("unrecognised user handle")
	}
	// The credential must actually belong to that account, so a valid handle
	// cannot be paired with somebody else's credential.
	cred, err := s.store.CredentialByID(base64.RawURLEncoding.EncodeToString(rawID))
	if err != nil || cred.UserID != user.ID {
		return nil, fmt.Errorf("credential does not belong to that account")
	}
	return s.webAuthnUserFor(user)
}

// handlePasskeyFinish verifies a usernameless assertion and starts the session.
func (s *Server) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.takeCeremony(w, r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no sign-in in progress — start again")
		return
	}
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, cred, err := wa.FinishPasskeyLogin(s.discoverableUser, cer.session, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "passkey rejected: "+protocolErr(err))
		return
	}
	au, ok := wu.(*webAuthnUser)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "could not resolve account")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	if cred.Authenticator.CloneWarning {
		s.recordAccountEvent(store.EventKeyCloneWarning, au.user.Email, au.user.Email,
			"sign counter went backwards for a security key — possible clone")
		writeErr(w, http.StatusUnauthorized, "passkey rejected: sign counter went backwards, which can mean the key was cloned")
		return
	}
	_ = s.store.TouchCredential(id, cred.Authenticator.SignCount)
	if err := s.startSession(w, au.user); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": au.user})
}

// handleWebAuthnLoginFinish verifies the assertion and starts the session.
func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.takeCeremony(w, r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no sign-in in progress — start again")
		return
	}
	user, err := s.store.GetUserByID(cer.userID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	wa, err := s.webAuthnFor(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wu, err := s.webAuthnUserFor(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load credentials")
		return
	}
	cred, err := wa.FinishLogin(wu, cer.session, r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "security key rejected: "+protocolErr(err))
		return
	}
	// A counter that goes backwards is the signature of a cloned authenticator.
	// Many keys pin it at zero, which the spec allows, so only a genuine
	// regression from a non-zero value is worth refusing.
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	if cred.Authenticator.CloneWarning {
		s.recordAccountEvent(store.EventKeyCloneWarning, user.Email, user.Email,
			"sign counter went backwards for a security key — possible clone")
		writeErr(w, http.StatusUnauthorized, "security key rejected: sign counter went backwards, which can mean the key was cloned")
		return
	}
	_ = s.store.TouchCredential(id, cred.Authenticator.SignCount)
	if err := s.startSession(w, user); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

// --- management -------------------------------------------------------------

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	creds, err := s.store.CredentialsForUser(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list credentials")
		return
	}
	if creds == nil {
		creds = []*model.WebAuthnCredential{}
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteCredential(id, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not remove credential")
		return
	}
	s.recordAccountEvent(store.EventKeyRemoved, u.Email, u.Email, "removed a security key")
	w.WriteHeader(http.StatusNoContent)
}

// protocolErr unwraps the library's error detail, which carries the actual
// reason ("challenge mismatch", "origin not allowed") behind a generic message.
func protocolErr(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		if pe.DevInfo != "" {
			return pe.Details + " (" + pe.DevInfo + ")"
		}
		return pe.Details
	}
	return err.Error()
}
