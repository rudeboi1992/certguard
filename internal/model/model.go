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

	// Operational state.
	AutoRescan    bool       `json:"auto_rescan"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Notes         string     `json:"notes,omitempty"`
	Active        bool       `json:"active"`
	CreatedAt     time.Time  `json:"created_at"`

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
