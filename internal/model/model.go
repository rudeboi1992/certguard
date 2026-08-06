// Package model holds the core domain types shared across storage, API, and UI.
package model

import "time"

// Kind describes how a tracked item is sourced and monitored.
type Kind string

const (
	// KindEndpoint is a live host:port scanned over TLS.
	KindEndpoint Kind = "endpoint"
	// KindFile is a certificate parsed from an uploaded/dropped file.
	KindFile Kind = "file"
	// KindManual is a hand-entered expiry (API keys, offline certs, anything).
	KindManual Kind = "manual"
	// KindDomain is a domain registration refreshed over RDAP. It is a Kind
	// rather than just a Category because it changes how the entry is
	// refreshed: the scheduler asks a registry instead of opening a socket.
	KindDomain Kind = "domain"
)

// Cert is a tracked certificate or credential. It generalizes the original
// ExpiryGuard "secret" (name + expiry) with the metadata an active scanner can
// discover, while preserving the notification-escalation state fields.
type Cert struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Category is a free "type" label — certificate, api-key, subscription,
	// domain, service, etc. Blank for older/unlabeled entries.
	Category string `json:"category"`

	// Endpoint coordinates (KindEndpoint only).
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	// Discovered certificate metadata (nil/zero until first observed).
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	KeyType   string    `json:"key_type,omitempty"`
	SigAlg    string    `json:"signature_algorithm,omitempty"`

	// Coverage is the last observed answer to "which certificate actually
	// serves each name this one covers". Persisted so a broken name — a SAN
	// that no longer resolves, and will fail the next HTTP-01 renewal for the
	// whole certificate — shows up on the dashboard instead of only when
	// somebody presses the check button.
	Coverage   []CoveredName `json:"coverage,omitempty"`
	CoverageAt *time.Time    `json:"coverage_at,omitempty"`

	// Operational state.
	AutoRescan    bool       `json:"auto_rescan"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Notes         string     `json:"notes,omitempty"`
	Active        bool       `json:"active"`
	CreatedAt     time.Time  `json:"created_at"`

	// Encrypted secret vault (optional). SecretEnc is the AES-256-GCM ciphertext
	// and is NEVER serialized to clients; the API exposes only whether a secret
	// is set and a masked hint. The plaintext is returned solely by the explicit
	// admin "reveal" endpoint.
	SecretEnc  string `json:"-"`
	HasSecret  bool   `json:"has_secret"`
	SecretHint string `json:"secret_hint,omitempty"`

	// Notification escalation state (ported from the original design):
	// LastNotifiedThreshold is 30, 7, 3, or 0 (never). A notification fires only
	// when moving to a more urgent threshold, preventing duplicate spam.
	LastNotifiedThreshold int        `json:"last_notified_threshold"`
	LastNotifiedOn        *time.Time `json:"last_notified_on,omitempty"`
}

// DaysRemaining reports whole days from now until expiry (may be negative).
func (c *Cert) DaysRemaining(now time.Time) int {
	return int(c.ExpiresAt.Sub(now).Hours() / 24)
}

// CoveredName records what one of a certificate's SAN entries actually serves.
// Status is match | different | wildcard | unreachable.
type CoveredName struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Subject string `json:"subject,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}
