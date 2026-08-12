package server

import (
	"encoding/json"
	"io"
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

func TestPasswordlessBeginDemandsUserVerification(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "pk@x.com", "supersecret", "admin")
	u, _ := st.GetUserByEmail("pk@x.com")
	if _, err := st.AddCredential(credFixture(u.ID)); err != nil {
		t.Fatal(err)
	}

	// httptest listens on 127.0.0.1, which the RP-ID guard rightly refuses, so
	// the request carries a hostname the way a real browser would.
	begin := func(payload string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth/webauthn/begin",
			strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "certguard.test"
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf strings.Builder
		_, _ = io.Copy(&buf, resp.Body)
		return resp.StatusCode, buf.String()
	}

	// No password: the key is the only factor, so the authenticator must verify
	// the user. Without this a stolen key alone would be a valid sign-in.
	code, body := begin(`{"email":"pk@x.com"}`)
	if code != http.StatusOK {
		t.Fatalf("passwordless begin = %d, want 200: %s", code, body)
	}
	if !strings.Contains(body, `"userVerification":"required"`) {
		t.Errorf("passwordless challenge does not require user verification: %s", body)
	}

	// With a correct password the key is a second factor, so verification is
	// not forced — the password already carried that half.
	code, body = begin(`{"email":"pk@x.com","password":"supersecret"}`)
	if code != http.StatusOK {
		t.Fatalf("second-factor begin = %d, want 200: %s", code, body)
	}
	if strings.Contains(body, `"userVerification":"required"`) {
		t.Errorf("second-factor challenge should not force verification: %s", body)
	}

	// A wrong password must not be treated as "no password given" and silently
	// promoted to the passwordless path.
	if code, _ = begin(`{"email":"pk@x.com","password":"wrong-password"}`); code != http.StatusUnauthorized {
		t.Errorf("wrong password = %d, want 401", code)
	}
}

// beginPasskey posts to the usernameless route with a hostname, since httptest
// listens on an IP the RP-ID guard rightly refuses.
func beginPasskey(t *testing.T, hs *httptest.Server) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth/passkey/begin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "certguard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, resp.Body)
	return resp.StatusCode, buf.String()
}

// The reason this route exists: an instance on the public internet must not
// answer differently depending on who is registered. Anything that varies with
// the account list is an enumeration oracle.
func TestPasskeyBeginRevealsNothingAboutAccounts(t *testing.T) {
	empty, _ := testServer(t)
	codeEmpty, bodyEmpty := beginPasskey(t, empty)
	if codeEmpty != http.StatusOK {
		t.Fatalf("passkey begin on an empty instance = %d, want 200: %s", codeEmpty, bodyEmpty)
	}

	populated, st := testServer(t)
	mkUser(t, st, "someone@x.com", "supersecret", "admin")
	u, _ := st.GetUserByEmail("someone@x.com")
	if _, err := st.AddCredential(credFixture(u.ID)); err != nil {
		t.Fatal(err)
	}
	codeFull, bodyFull := beginPasskey(t, populated)
	if codeFull != codeEmpty {
		t.Errorf("status differs with accounts present: %d vs %d", codeFull, codeEmpty)
	}

	// The challenge is random per call, so compare the shape rather than bytes:
	// no credential list may appear, and no address may be echoed.
	var withUsers, without map[string]any
	if err := json.Unmarshal([]byte(bodyFull), &withUsers); err != nil {
		t.Fatalf("unmarshal populated: %v — %s", err, bodyFull)
	}
	if err := json.Unmarshal([]byte(bodyEmpty), &without); err != nil {
		t.Fatalf("unmarshal empty: %v — %s", err, bodyEmpty)
	}
	pkFull, _ := withUsers["publicKey"].(map[string]any)
	pkEmpty, _ := without["publicKey"].(map[string]any)
	if pkFull == nil || pkEmpty == nil {
		t.Fatalf("no publicKey in response: %s / %s", bodyFull, bodyEmpty)
	}
	if allow, ok := pkFull["allowCredentials"]; ok {
		if list, isList := allow.([]any); isList && len(list) > 0 {
			t.Errorf("challenge names credentials, which identifies the account: %v", list)
		}
	}
	if len(pkFull) != len(pkEmpty) {
		t.Errorf("response shape differs with accounts present: %v vs %v", pkFull, pkEmpty)
	}
	if strings.Contains(bodyFull, "someone@x.com") {
		t.Error("challenge echoes an account address")
	}
	// A passkey is the only factor here, so verification must be demanded.
	if pkFull["userVerification"] != "required" {
		t.Errorf("userVerification = %v, want required", pkFull["userVerification"])
	}
}

func TestPasskeyFinishRejectsAStrayCeremony(t *testing.T) {
	hs, _ := testServer(t)
	// No begin, so no ceremony cookie: finish must refuse rather than fall
	// through to anything.
	req, _ := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth/passkey/finish",
		strings.NewReader(`{}`))
	req.Host = "certguard.test"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("finish without a ceremony = %d, want 400", resp.StatusCode)
	}
}
