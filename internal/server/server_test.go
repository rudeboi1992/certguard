package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/auth"
	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/store"
	"github.com/bfalcher/certguard/internal/twofa"
)

// currentTOTP computes the code an authenticator would show right now.
func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := twofa.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := config.Config{SessionTTL: time.Hour, ScanTimeout: 5 * time.Second}
	srv := New(cfg, st, nil)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, st
}

func mkUser(t *testing.T, st *store.Store, email, pw, role string) {
	t.Helper()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(email, hash, role); err != nil {
		t.Fatal(err)
	}
}

func TestCertsRequireAuth(t *testing.T) {
	hs, _ := testServer(t)
	resp, err := http.Get(hs.URL + "/api/v1/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /certs = %d, want 401", resp.StatusCode)
	}
}

func TestHealthIsPublic(t *testing.T) {
	hs, _ := testServer(t)
	resp, err := http.Get(hs.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", resp.StatusCode)
	}
}

func login(t *testing.T, hs *httptest.Server, client *http.Client, email, pw string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	resp, err := client.Post(hs.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestSessionLoginFlow(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "admin@x.com", "supersecret", "admin")

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	if code := login(t, hs, client, "admin@x.com", "wrongpassword"); code != http.StatusUnauthorized {
		t.Errorf("bad-password login = %d, want 401", code)
	}
	if code := login(t, hs, client, "admin@x.com", "supersecret"); code != http.StatusOK {
		t.Fatalf("good login = %d, want 200", code)
	}
	// Cookie from login should now authorize /certs.
	resp, err := client.Get(hs.URL + "/api/v1/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated /certs = %d, want 200", resp.StatusCode)
	}
}

func TestBearerTokenAuth(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "bot@x.com", "supersecret", "viewer")
	u, _ := st.GetUserByEmail("bot@x.com")
	plaintext, _ := auth.GenerateToken()
	if _, err := st.CreateToken(u.ID, "ci", auth.HashSecret(plaintext)); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", hs.URL+"/api/v1/certs", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bearer-auth /certs = %d, want 200", resp.StatusCode)
	}

	// A bogus token must be rejected.
	req2, _ := http.NewRequest("GET", hs.URL+"/api/v1/certs", nil)
	req2.Header.Set("Authorization", "Bearer cg_notarealtoken")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("bogus-token /certs = %d, want 401", resp2.StatusCode)
	}
}

func TestViewerCannotScan(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "viewer@x.com", "supersecret", "viewer")
	u, _ := st.GetUserByEmail("viewer@x.com")
	plaintext, _ := auth.GenerateToken()
	st.CreateToken(u.ID, "", auth.HashSecret(plaintext))

	body, _ := json.Marshal(map[string]any{"target": "example.com", "dry_run": true})
	req, _ := http.NewRequest("POST", hs.URL+"/api/v1/scan", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer scan = %d, want 403", resp.StatusCode)
	}
}

func TestAdminCanScanViaAPI(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "admin@x.com", "supersecret", "admin")
	u, _ := st.GetUserByEmail("admin@x.com")
	plaintext, _ := auth.GenerateToken()
	st.CreateToken(u.ID, "", auth.HashSecret(plaintext))

	// A local TLS server gives us a real endpoint to scan.
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(tls.Close)
	target := tls.Listener.Addr().String()

	body, _ := json.Marshal(map[string]any{"target": target, "dry_run": true})
	req, _ := http.NewRequest("POST", hs.URL+"/api/v1/scan", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin scan = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Scan struct {
			SHA256 string `json:"sha256"`
		} `json:"scan"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if len(out.Scan.SHA256) != 64 {
		t.Errorf("scan result missing fingerprint: %q", out.Scan.SHA256)
	}
}

func TestSanitizeLabelDropsControlChars(t *testing.T) {
	cases := map[string]string{
		"api.example.com":     "api.example.com",
		"web\r\nBcc: x@y.com": "webBcc: x@y.com",
		"  spaced  ":          "spaced",
		"tab\tinside":         "tab\tinside", // tabs are kept
		"nul\x00byte":         "nulbyte",
		"\x1b[31mansi\x1b[0m": "[31mansi[0m",
		"café résumé":         "café résumé", // unicode preserved
	}
	for in, want := range cases {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginRejectsReplayedTOTPCode(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "totp@x.com", "supersecret", "admin")
	u, _ := st.GetUserByEmail("totp@x.com")

	secret, err := twofa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserTOTP(u.ID, secret, true); err != nil {
		t.Fatal(err)
	}
	code := currentTOTP(t, secret)

	login := func() int {
		body, _ := json.Marshal(map[string]string{
			"email": "totp@x.com", "password": "supersecret", "code": code,
		})
		resp, err := http.Post(hs.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code1 := login(); code1 != http.StatusOK {
		t.Fatalf("first login with a fresh code = %d, want 200", code1)
	}
	// Same code, immediately: the replay guard must reject it even though the
	// code is still within its time window.
	if code2 := login(); code2 == http.StatusOK {
		t.Error("replayed TOTP code was accepted on the second login")
	}
}
