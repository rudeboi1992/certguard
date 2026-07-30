package server

import (
	"encoding/json"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

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
