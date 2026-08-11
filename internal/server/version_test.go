package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestVersionRequiresAuth(t *testing.T) {
	hs, _ := testServer(t)
	resp, err := http.Get(hs.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /version = %d, want 401", resp.StatusCode)
	}
}

func TestVersionReportsBuild(t *testing.T) {
	hs, st := testServer(t)
	mkUser(t, st, "viewer@x.com", "supersecret", "viewer")

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if code := login(t, hs, client, "viewer@x.com", "supersecret"); code != http.StatusOK {
		t.Fatalf("login = %d, want 200", code)
	}

	resp, err := client.Get(hs.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/version = %d, want 200", resp.StatusCode)
	}
	var v VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	// A viewer can read it, so it must carry nothing deployment-specific.
	if v.Version == "" {
		t.Error("version is empty")
	}
	if v.GoVersion == "" || v.OS == "" || v.Arch == "" {
		t.Errorf("runtime fields incomplete: %+v", v)
	}
}

func TestSetBuildInfoIgnoresEmpty(t *testing.T) {
	origV, origC, origD := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = origV, origC, origD })

	SetBuildInfo("v9.9.9", "abc123", "2026-01-01T00:00:00Z")
	// An unstamped field must not blank out what is already known, or a
	// partially stamped build would report less than an unstamped one.
	SetBuildInfo("", "", "")
	if Version != "v9.9.9" || Commit != "abc123" || BuildDate != "2026-01-01T00:00:00Z" {
		t.Errorf("empty args overwrote build info: %s %s %s", Version, Commit, BuildDate)
	}
	if got := BuildInfo(); got.Version != "v9.9.9" {
		t.Errorf("BuildInfo().Version = %q, want v9.9.9", got.Version)
	}
}
