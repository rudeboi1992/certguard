package model

import "time"

// User is an authenticated principal. Certs are a shared inventory across all
// users; Role gates whether a user may mutate that inventory.
type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // never serialized
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`

	// Two-factor (TOTP). TOTPSecret is the base32 shared secret and is never
	// serialized; TOTPEnabled reports whether 2FA is active for this user.
	TOTPSecret  string `json:"-"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

// IsAdmin reports whether the user may perform write operations.
func (u *User) IsAdmin() bool { return u.Role == "admin" }

// WebAuthnCredential is one registered security key. Field types are plain
// strings so this package stays free of the WebAuthn library — the server
// converts to and from the library's types at its boundary.
type WebAuthnCredential struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"-"`
	CredentialID string `json:"credential_id"` // base64url, the authenticator's handle
	// PublicKey is the COSE key used to verify assertions. Not a secret, but
	// there is no reason to hand it to the browser either.
	PublicKey      string     `json:"-"`
	AAGUID         string     `json:"aaguid,omitempty"`
	SignCount      uint32     `json:"-"`
	Transports     string     `json:"transports,omitempty"`
	Name           string     `json:"name"`
	BackupEligible bool       `json:"backup_eligible"`
	BackupState    bool       `json:"backup_state"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`

	// UnlocksVault reports whether this key also carries a wrapped copy of the
	// vault data key. Derived at read time from vault_key_wrappers.
	UnlocksVault bool `json:"unlocks_vault"`
}

// APIToken is a long-lived bearer credential for automation. Only its hash is
// stored; Plaintext is populated only at creation time, for one-time display.
type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Plaintext  string     `json:"plaintext,omitempty"`
}
