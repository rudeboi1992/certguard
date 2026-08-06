// Package rdap looks up domain registration expiry over RDAP, the JSON protocol
// that replaced WHOIS.
//
// It exists because a certificate and the domain under it are two separate
// clocks. A certificate renews every 90 days and fails on validation; a domain
// renews yearly and fails because a card on file expired. certguard can see the
// first by connecting; this is how it sees the second.
//
// The shape deliberately mirrors internal/scanner: Lookup returns data or an
// error, and a domain that is merely close to expiry is data, not a failure.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// DefaultBase is the IANA-backed redirector. It answers for every gTLD and
// forwards to the authoritative registry, which saves shipping and refreshing a
// copy of the bootstrap table.
const DefaultBase = "https://rdap.org"

// DefaultTimeout bounds a single lookup.
const DefaultTimeout = 12 * time.Second

var (
	// ErrNotRegistered is a 404 from the registry: nothing holds this name.
	ErrNotRegistered = errors.New("domain is not registered")
	// ErrNoExpiry means the registry answered but published no expiration
	// event. Common on ccTLDs (.de and .co.uk among others), so callers should
	// treat it as "cannot track this one", not as a fault.
	ErrNoExpiry = errors.New("registry published no expiration date")
)

// Options tunes a lookup.
type Options struct {
	// Timeout bounds the request. Zero means DefaultTimeout.
	Timeout time.Duration
	// BaseURL overrides the RDAP endpoint. Zero value means DefaultBase.
	// Tests point this at an httptest server.
	BaseURL string
	// Client overrides the HTTP client.
	Client *http.Client
}

// Result is the flattened, storable view of a domain registration.
type Result struct {
	Domain       string    `json:"domain"`
	Registrar    string    `json:"registrar,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	RegisteredAt time.Time `json:"registered_at,omitempty"`
	// Status carries EPP codes such as clientTransferProhibited. A domain with
	// no lock set is materially easier to lose, so it is worth surfacing.
	Status      []string `json:"status,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
}

// DaysUntilExpiry reports whole days from now until ExpiresAt (may be negative).
func (r *Result) DaysUntilExpiry(now time.Time) int {
	return int(r.ExpiresAt.Sub(now).Hours() / 24)
}

// Registrable reduces a hostname to the domain that is actually registered:
// www.cpigaugescom.uniweldproducts.com to uniweldproducts.com. It uses the
// Public Suffix List rather than taking the last two labels, which would turn
// shop.example.co.uk into the unregistrable co.uk.
func Registrable(host string) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return "", errors.New("empty host")
	}
	// A wildcard SAN is not a host; its parent is the interesting part.
	h = strings.TrimPrefix(h, "*.")
	if strings.ContainsAny(h, ":/ ") {
		return "", fmt.Errorf("not a bare hostname: %q", host)
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return "", err
	}
	return d, nil
}

// rdapDomain is the subset of the RDAP domain object we consume.
type rdapDomain struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles []string        `json:"roles"`
		VCard json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

// Lookup fetches the registration record for a domain. The argument may be any
// hostname — it is reduced to the registrable domain first, since registries
// only answer for that.
func Lookup(ctx context.Context, host string, opts Options) (*Result, error) {
	domain, err := Registrable(host)
	if err != nil {
		return nil, err
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultBase
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(base, "/")+"/domain/"+domain, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotRegistered
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("rdap: %s returned %s", domain, resp.Status)
	}

	var d rdapDomain
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("rdap: malformed response for %s: %w", domain, err)
	}

	out := &Result{Domain: domain, Status: d.Status}
	for _, e := range d.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		switch e.Action {
		case "expiration":
			out.ExpiresAt = t.UTC()
		case "registration":
			out.RegisteredAt = t.UTC()
		}
	}
	if out.ExpiresAt.IsZero() {
		return nil, ErrNoExpiry
	}
	for _, ns := range d.Nameservers {
		if ns.LDHName != "" {
			out.Nameservers = append(out.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, e := range d.Entities {
		if !hasRole(e.Roles, "registrar") {
			continue
		}
		if n := vcardField(e.VCard, "fn"); n != "" {
			out.Registrar = n
			break
		}
	}
	return out, nil
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardField digs a named field out of a jCard. The format is awkward — a
// two-element array whose second element is a list of ["name", {}, "type",
// value] tuples — so it is decoded loosely rather than modelled.
func vcardField(raw json.RawMessage, want string) string {
	if len(raw) == 0 {
		return ""
	}
	var card []any
	if err := json.Unmarshal(raw, &card); err != nil || len(card) < 2 {
		return ""
	}
	fields, ok := card[1].([]any)
	if !ok {
		return ""
	}
	for _, f := range fields {
		tuple, ok := f.([]any)
		if !ok || len(tuple) < 4 {
			continue
		}
		if name, _ := tuple[0].(string); !strings.EqualFold(name, want) {
			continue
		}
		if v, ok := tuple[3].(string); ok {
			return v
		}
	}
	return ""
}
