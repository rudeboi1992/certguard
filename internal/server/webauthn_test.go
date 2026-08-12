package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
)

func TestRPConfigRejectsIPHosts(t *testing.T) {
	// The whole reason security keys cannot be used on https://192.168.0.154:
	// the spec requires a domain, and a browser would otherwise throw an opaque
	// SecurityError. Fail early with something an operator can act on.
	s := &Server{cfg: config.Config{}}
	for _, host := range []string{"192.168.0.154", "192.168.0.154:443", "127.0.0.1:8181", "[::1]:8181"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
		r.Host = host
		_, _, err := s.rpConfig(r)
		if err == nil {
			t.Errorf("rpConfig(%q) = nil error, want a refusal", host)
			continue
		}
		if !strings.Contains(err.Error(), "domain name") {
			t.Errorf("rpConfig(%q) error = %q, want it to explain the domain requirement", host, err)
		}
	}
}

func TestRPConfigDerivesFromHost(t *testing.T) {
	s := &Server{cfg: config.Config{}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
	r.Host = "certguard.unifl.local:443"
	id, origins, err := s.rpConfig(r)
	if err != nil {
		t.Fatalf("rpConfig: %v", err)
	}
	// The RP ID is the host without its port; the origin keeps it.
	if id != "certguard.unifl.local" {
		t.Errorf("RPID = %q, want certguard.unifl.local", id)
	}
	if len(origins) != 1 || origins[0] != "http://certguard.unifl.local:443" {
		t.Errorf("origins = %v, want the request origin", origins)
	}
}

func TestRPConfigPrefersExplicitSettings(t *testing.T) {
	// Behind a proxy that rewrites Host, configuration has to win.
	s := &Server{cfg: config.Config{
		RPID:      "certguard.unifl.local",
		RPOrigins: []string{"https://certguard.unifl.local"},
	}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/register/begin", nil)
	r.Host = "10.0.0.5:8181" // an IP, which would otherwise be refused
	id, origins, err := s.rpConfig(r)
	if err != nil {
		t.Fatalf("rpConfig with explicit RPID: %v", err)
	}
	if id != "certguard.unifl.local" || len(origins) != 1 {
		t.Errorf("got id=%q origins=%v, want the configured values", id, origins)
	}
}

func TestLoginAdvertisesSecondFactorMethods(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "keys@x.com", "supersecret", "admin")
	u, _ := st.GetUserByEmail("keys@x.com")

	// No second factor yet: password alone signs in.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if code := login(t, hs, client, "keys@x.com", "supersecret"); code != http.StatusOK {
		t.Fatalf("login without 2FA = %d, want 200", code)
	}

	// Register a credential directly, then the same login must ask for it.
	if _, err := st.AddCredential(credFixture(u.ID)); err != nil {
		t.Fatal(err)
	}
	jar2, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar2}
	body := strings.NewReader(`{"email":"keys@x.com","password":"supersecret"}`)
	resp, err := client2.Post(hs.URL+"/api/v1/auth/login", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with a key registered = %d, want 401", resp.StatusCode)
	}
	var out struct {
		Error   string   `json:"error"`
		Methods []string `json:"methods"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "2fa_required" {
		t.Errorf("error = %q, want 2fa_required", out.Error)
	}
	// TOTP is off, so a key must be the only method offered — otherwise the
	// login page would show a code box nobody can satisfy.
	if len(out.Methods) != 1 || out.Methods[0] != "webauthn" {
		t.Errorf("methods = %v, want [webauthn]", out.Methods)
	}
}

// credFixture is a syntactically valid stored credential. It is never asserted
// against — these tests cover the paths around WebAuthn, not the ceremony
// itself, which needs a real authenticator.
func credFixture(userID int64) *model.WebAuthnCredential {
	return &model.WebAuthnCredential{
		UserID:       userID,
		CredentialID: "dGVzdC1jcmVkZW50aWFsLWlk",
		PublicKey:    "dGVzdC1wdWJsaWMta2V5",
		Name:         "Test key",
	}
}
