// Package auth holds the security primitives shared by the store, server, and
// CLI: password hashing, API-token generation, and session-id generation.
//
// Design notes:
//   - Passwords are bcrypt-hashed.
//   - API tokens and session ids are high-entropy random secrets. We store only
//     their SHA-256 hash, never the plaintext, so a database leak does not hand
//     an attacker usable credentials. The plaintext is shown to the user exactly
//     once, at creation time.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Role gates what an authenticated user may do.
type Role string

const (
	RoleAdmin  Role = "admin"  // may add/delete/scan
	RoleViewer Role = "viewer" // read-only
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleAdmin || r == RoleViewer }

// TokenPrefix / SessionPrefix make secrets self-identifying in logs and configs
// without weakening them.
const (
	TokenPrefix   = "cg_"
	SessionPrefix = "cs_"
)

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword reports whether pw matches the stored bcrypt hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// newSecret returns `prefix` followed by 32 bytes of base64url-encoded entropy.
func newSecret(prefix string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateToken returns a new plaintext API token. Store HashSecret(token).
func GenerateToken() (string, error) { return newSecret(TokenPrefix) }

// GenerateSession returns a new plaintext session id. Store HashSecret(id).
func GenerateSession() (string, error) { return newSecret(SessionPrefix) }

// HashSecret returns the lowercase-hex SHA-256 of a token or session id. This
// is what gets stored and looked up; the plaintext is never persisted.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SecretsEqual compares two hex hashes in constant time.
func SecretsEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// BearerToken extracts the token from an "Authorization: Bearer <t>" header
// value, returning "" if the header is absent or malformed.
func BearerToken(header string) string {
	const p = "Bearer "
	if len(header) > len(p) && strings.EqualFold(header[:len(p)], p) {
		return strings.TrimSpace(header[len(p):])
	}
	return ""
}
