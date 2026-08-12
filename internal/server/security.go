package server

import (
	"encoding/json"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/store"
	"github.com/bfalcher/certguard/internal/twofa"
)

// handle2FAQR renders the current (pending or active) TOTP secret as a QR code
// PNG for the authenticated user to scan.
func (s *Server) handle2FAQR(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUserByID(userFrom(r.Context()).ID)
	if err != nil || u.TOTPSecret == "" {
		writeErr(w, http.StatusNotFound, "no authenticator secret; start setup first")
		return
	}
	png, err := qrcode.Encode(twofa.ProvisioningURI(u.TOTPSecret, u.Email, "certguard"), qrcode.Medium, 240)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// --- secret vault: lock / unlock / passphrase ---

func (s *Server) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	enabled, unlocked, passphrase := s.vault.status()
	writeJSON(w, http.StatusOK, map[string]bool{
		"enabled": enabled, "unlocked": unlocked, "passphrase": passphrase,
	})
}

func (s *Server) handleVaultUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.vault.unlock(req.Passphrase); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

func (s *Server) handleVaultLock(w http.ResponseWriter, r *http.Request) {
	s.vault.lock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

// handleVaultPassphrase sets, changes, or (with an empty new passphrase) removes
// the vault passphrase. The vault must be unlocked.
func (s *Server) handleVaultPassphrase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current_passphrase"`
		New     string `json:"new_passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.New != "" && len(req.New) < 8 {
		writeErr(w, http.StatusBadRequest, "passphrase must be at least 8 characters")
		return
	}
	if err := s.vault.setPassphrase(req.Current, req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- zero-knowledge keyring ---

func (s *Server) handleZKKeyringGet(w http.ResponseWriter, r *http.Request) {
	if !s.vault.zkOn() {
		writeErr(w, http.StatusNotFound, "zero-knowledge mode is not enabled")
		return
	}
	wrapped, salt, iters := s.vault.zkKeyring()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"wrapped": wrapped, "salt": salt, "iters": iters})
}

type zkKeyringReq struct {
	Wrapped string `json:"wrapped"`
	Salt    string `json:"salt"`
	Iters   string `json:"iters"`
	// Optional: client ciphertext for existing entries, re-encrypted during the
	// switch to zero-knowledge (so nothing is lost).
	Secrets []struct {
		ID   int64  `json:"id"`
		Enc  string `json:"enc"`
		Hint string `json:"hint"`
	} `json:"secrets"`
}

// handleZKKeyringSet enables zero-knowledge mode (or rotates the passphrase by
// re-wrapping the same data key). The server stores the client-produced keyring;
// it never sees the passphrase or any plaintext.
func (s *Server) handleZKKeyringSet(w http.ResponseWriter, r *http.Request) {
	var req zkKeyringReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Wrapped == "" || req.Salt == "" || req.Iters == "" {
		writeErr(w, http.StatusBadRequest, "wrapped, salt, and iters are required")
		return
	}
	// Turning zero-knowledge ON generates a brand new data key in the browser,
	// so any security-key wrappers hold a key that no longer opens anything.
	// Rotating the passphrase while it is already on re-wraps the SAME data
	// key, and those wrappers stay valid — which is the point of storing them
	// separately from the passphrase keyring.
	wasOn := s.vault.zkOn()
	if err := s.vault.enableZK(req.Wrapped, req.Salt, req.Iters); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !wasOn {
		// Dropped deliberately: zero-knowledge mode is already on at this
		// point, and failing the request now would be worse than a stale row.
		// A surviving wrapper cannot leak or corrupt anything either — it holds
		// the old data key, so unwrapping with it fails the AES-GCM tag check
		// and the user is told the key does not open the vault.
		_ = s.store.ClearVaultWrappers()
	}
	// Store any migrated ciphertext verbatim.
	for _, sec := range req.Secrets {
		_ = s.store.SetSecret(sec.ID, sec.Enc, sec.Hint)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleZKKeyringDelete leaves zero-knowledge mode; secrets are wiped (their
// ciphertext is unreadable without the client key) and the server keyring is
// restored.
func (s *Server) handleZKKeyringDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.vault.disableZK(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The data key those wrappers hold is gone with the keyring. Dropped for
	// the same reason as in the enable path.
	_ = s.store.ClearVaultWrappers()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- vault unlock by security key -------------------------------------------

type vaultWrapperReq struct {
	Wrapped string `json:"wrapped"`
	PRFSalt string `json:"prf_salt"`
}

// ownedCredential resolves a credential ID from the path and confirms it
// belongs to the caller, so one account cannot touch another's keys.
func (s *Server) ownedCredential(r *http.Request) (*model.WebAuthnCredential, error) {
	u := userFrom(r.Context())
	c, err := s.store.CredentialByID(r.PathValue("cid"))
	if err != nil {
		return nil, err
	}
	if c.UserID != u.ID {
		return nil, store.ErrNoCredential
	}
	return c, nil
}

// handleVaultWrapperSet pairs a security key with the vault by storing the data
// key wrapped under that key's prf secret. The wrapping happened in the
// browser; the server is storing ciphertext it cannot open, exactly as it does
// for the passphrase keyring.
func (s *Server) handleVaultWrapperSet(w http.ResponseWriter, r *http.Request) {
	c, err := s.ownedCredential(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such security key")
		return
	}
	var req vaultWrapperReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Wrapped == "" || req.PRFSalt == "" {
		writeErr(w, http.StatusBadRequest, "wrapped and prf_salt are required")
		return
	}
	if err := s.store.SetVaultWrapper(c.CredentialID, req.Wrapped, req.PRFSalt); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store wrapper")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleVaultWrapperGet returns what the browser needs to unlock with a key.
// Useless without the physical key, but still scoped to the owner and marked
// no-store.
func (s *Server) handleVaultWrapperGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.ownedCredential(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such security key")
		return
	}
	wrapped, salt, err := s.store.VaultWrapper(c.CredentialID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "this key does not unlock the vault")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"wrapped": wrapped, "prf_salt": salt})
}

// handleVaultWrapperDelete stops a key from unlocking the vault without
// unregistering it as a second factor. Safe unconditionally: the passphrase
// wrapper is always present, so this can never orphan the vault.
func (s *Server) handleVaultWrapperDelete(w http.ResponseWriter, r *http.Request) {
	c, err := s.ownedCredential(r)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such security key")
		return
	}
	if err := s.store.DeleteVaultWrapper(c.CredentialID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not remove wrapper")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- two-factor (TOTP) ---

// handle2FASetup provisions a pending secret (not yet enforced) and returns it
// plus the otpauth URI so the user can add it to an authenticator app.
func (s *Server) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u.TOTPEnabled {
		writeErr(w, http.StatusConflict, "two-factor is already enabled")
		return
	}
	secret, err := twofa.GenerateSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetUserTOTP(u.ID, secret, false); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    twofa.ProvisioningURI(secret, u.Email, "certguard"),
	})
}

// handle2FAEnable verifies a code against the pending secret and turns 2FA on.
func (s *Server) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := s.store.GetUserByID(userFrom(r.Context()).ID)
	if err != nil || u.TOTPSecret == "" {
		writeErr(w, http.StatusBadRequest, "start setup first")
		return
	}
	if !twofa.Validate(u.TOTPSecret, req.Code) {
		writeErr(w, http.StatusBadRequest, "incorrect code")
		return
	}
	if err := s.store.SetUserTOTP(u.ID, u.TOTPSecret, true); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

// handle2FADisable turns 2FA off after verifying a current code.
func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := s.store.GetUserByID(userFrom(r.Context()).ID)
	if err != nil || !u.TOTPEnabled {
		writeErr(w, http.StatusBadRequest, "two-factor is not enabled")
		return
	}
	if !twofa.Validate(u.TOTPSecret, req.Code) {
		writeErr(w, http.StatusBadRequest, "incorrect code")
		return
	}
	if err := s.store.SetUserTOTP(u.ID, "", false); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}
