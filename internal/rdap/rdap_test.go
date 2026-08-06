package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistrable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"uniweldproducts.com", "uniweldproducts.com"},
		{"www.cpigaugescom.uniweldproducts.com", "uniweldproducts.com"},
		{"UNIWELD.COM", "uniweld.com"},
		{"uniweld.com.", "uniweld.com"},
		// A wildcard SAN reduces to its parent rather than erroring, so callers
		// can feed a certificate's whole SAN list in unfiltered.
		{"*.uniweldproducts.com", "uniweldproducts.com"},
		// The reason this uses the Public Suffix List: last-two-labels would
		// yield co.uk, which nobody can register.
		{"shop.example.co.uk", "example.co.uk"},
		{"unibox.biz", "unibox.biz"},
	}
	for _, c := range cases {
		got, err := Registrable(c.in)
		if err != nil {
			t.Errorf("Registrable(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Registrable(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "   ", "host:443", "http://x.com"} {
		if _, err := Registrable(bad); err == nil {
			t.Errorf("Registrable(%q) should have failed", bad)
		}
	}
}

// A trimmed but structurally faithful Verisign-style response.
const sample = `{
  "objectClassName": "domain",
  "ldhName": "UNIWELD.COM",
  "status": ["client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1996-01-19T05:00:00Z"},
    {"eventAction": "expiration",   "eventDate": "2030-01-20T05:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2025-12-02T09:11:00Z"}
  ],
  "entities": [
    {"roles": ["registrar"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                              ["fn", {}, "text", "Bluehost Inc."]]]}
  ],
  "nameservers": [{"ldhName": "NS1.BLUEHOST.COM"}, {"ldhName": "NS2.BLUEHOST.COM"}]
}`

func serve(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/uniweld.com" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestLookup(t *testing.T) {
	srv := serve(t, http.StatusOK, sample)
	defer srv.Close()

	// Given a subdomain, the lookup should still hit the registrable domain.
	res, err := Lookup(context.Background(), "mail.uniweld.com", Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Domain != "uniweld.com" {
		t.Errorf("Domain = %q", res.Domain)
	}
	want := time.Date(2030, 1, 20, 5, 0, 0, 0, time.UTC)
	if !res.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", res.ExpiresAt, want)
	}
	if res.RegisteredAt.Year() != 1996 {
		t.Errorf("RegisteredAt = %v", res.RegisteredAt)
	}
	if res.Registrar != "Bluehost Inc." {
		t.Errorf("Registrar = %q", res.Registrar)
	}
	if len(res.Status) != 1 || res.Status[0] != "client transfer prohibited" {
		t.Errorf("Status = %v", res.Status)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0] != "ns1.bluehost.com" {
		t.Errorf("Nameservers = %v", res.Nameservers)
	}
}

func TestLookupNotRegistered(t *testing.T) {
	srv := serve(t, http.StatusNotFound, `{"errorCode":404}`)
	defer srv.Close()
	_, err := Lookup(context.Background(), "uniweld.com", Options{BaseURL: srv.URL})
	if !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("err = %v, want ErrNotRegistered", err)
	}
}

// Registries that publish no expiration event must be distinguishable from
// outright failures — the caller reports "cannot track", not "lookup broke".
func TestLookupNoExpiry(t *testing.T) {
	srv := serve(t, http.StatusOK, `{"ldhName":"UNIWELD.COM","events":[
		{"eventAction":"registration","eventDate":"1996-01-19T05:00:00Z"}]}`)
	defer srv.Close()
	_, err := Lookup(context.Background(), "uniweld.com", Options{BaseURL: srv.URL})
	if !errors.Is(err, ErrNoExpiry) {
		t.Fatalf("err = %v, want ErrNoExpiry", err)
	}
}

func TestLookupServerError(t *testing.T) {
	srv := serve(t, http.StatusInternalServerError, `nope`)
	defer srv.Close()
	if _, err := Lookup(context.Background(), "uniweld.com", Options{BaseURL: srv.URL}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	r := &Result{ExpiresAt: now.AddDate(0, 0, 45)}
	if got := r.DaysUntilExpiry(now); got != 45 {
		t.Errorf("DaysUntilExpiry = %d, want 45", got)
	}
	expired := &Result{ExpiresAt: now.AddDate(0, 0, -3)}
	if got := expired.DaysUntilExpiry(now); got != -3 {
		t.Errorf("expired DaysUntilExpiry = %d, want -3", got)
	}
}
