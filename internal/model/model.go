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

	// Chain is the intermediate certificates the endpoint served alongside the
	// leaf. A leaf is only as good as the path under it: if an intermediate
	// lapses first, the endpoint breaks on that date, not on ExpiresAt. See
	// ChainRisk.
	Chain []ChainCert `json:"chain,omitempty"`

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

	// The chain escalates separately from the leaf. Sharing one counter would
	// let whichever fired first silence the other, which is precisely the
	// failure this feature exists to catch.
	LastChainNotifiedThreshold int `json:"last_chain_notified_threshold"`
}

// DaysRemaining reports whole days from now until expiry (may be negative).
func (c *Cert) DaysRemaining(now time.Time) int {
	return int(c.ExpiresAt.Sub(now).Hours() / 24)
}

// ChainCert is one intermediate the endpoint presented under the leaf. Roots
// are not included: servers are not required to send them, and the one that
// matters is whatever the client would have to build a path through.
type ChainCert struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"not_after"`
	SHA256   string    `json:"sha256,omitempty"`
}

// ChainRisk reports the soonest intermediate expiry that would break this
// endpoint before its own certificate does, and whether there is one.
//
// An intermediate expiring AFTER the leaf is deliberately not a risk: renewing
// the leaf on its own schedule fetches a fresh chain anyway, so warning about
// it would be noise on every endpoint whose CA happens to rotate on a longer
// cycle — which is all of them.
func (c *Cert) ChainRisk() (ChainCert, bool) {
	var soonest ChainCert
	found := false
	for _, ic := range c.Chain {
		if ic.NotAfter.IsZero() {
			continue
		}
		// Only a link that gives out before the leaf changes the outcome.
		if !c.ExpiresAt.IsZero() && !ic.NotAfter.Before(c.ExpiresAt) {
			continue
		}
		if !found || ic.NotAfter.Before(soonest.NotAfter) {
			soonest, found = ic, true
		}
	}
	return soonest, found
}

// ChainDaysRemaining reports whole days until the at-risk link expires. The
// bool is false when nothing in the chain expires before the leaf.
func (c *Cert) ChainDaysRemaining(now time.Time) (int, bool) {
	risk, ok := c.ChainRisk()
	if !ok {
		return 0, false
	}
	return int(risk.NotAfter.Sub(now).Hours() / 24), true
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

// Event is one line of the activity log: something that changed, when, and who
// or what changed it. CertID/CertName are denormalised because the log has to
// remain readable after the entry it refers to is deleted.
type Event struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	CertID   int64     `json:"cert_id,omitempty"`
	CertName string    `json:"cert_name,omitempty"`
	Actor    string    `json:"actor,omitempty"` // user email, or empty for the scheduler
	Detail   string    `json:"detail,omitempty"`
}
