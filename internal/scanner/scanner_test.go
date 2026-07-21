package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// startTLSServer spins up an httptest TLS server (self-signed leaf) and returns
// its host and port.
func startTLSServer(t *testing.T) (host string, port int, notAfter time.Time) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	u := srv.Listener.Addr().String()
	h, p, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	pn, _ := strconv.Atoi(p)
	// The leaf cert httptest uses.
	leaf := srv.Certificate()
	return h, pn, leaf.NotAfter
}

func TestScanReadsLeafCertificate(t *testing.T) {
	host, port, notAfter := startTLSServer(t)

	res, err := Scan(context.Background(), host, port, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if res.NotAfter.Unix() != notAfter.UTC().Unix() {
		t.Errorf("NotAfter = %v, want %v", res.NotAfter, notAfter.UTC())
	}
	if res.SHA256 == "" || len(res.SHA256) != 64 {
		t.Errorf("SHA256 fingerprint looks wrong: %q", res.SHA256)
	}
	if res.KeyType == "" || res.KeyType == "unknown" {
		t.Errorf("KeyType not detected: %q", res.KeyType)
	}
	// httptest's cert is self-signed against 127.0.0.1, so trust should fail
	// for a "localhost"/IP mismatch OR verify — either way the scan itself
	// must succeed and populate data. We assert only that a scan succeeded.
	if res.ChainLen < 1 {
		t.Errorf("ChainLen = %d, want >= 1", res.ChainLen)
	}
}

func TestScanRefusedConnectionIsError(t *testing.T) {
	// Port 1 is virtually never listening; expect a dial error, not a panic.
	_, err := Scan(context.Background(), "127.0.0.1", 1, Options{Timeout: 1 * time.Second})
	if err == nil {
		t.Fatal("expected error scanning closed port, got nil")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com", "example.com", 443, false},
		{"example.com:8443", "example.com", 8443, false},
		{"https://example.com/path", "example.com", 443, false},
		{"https://example.com:9000/x", "example.com", 9000, false},
		{"", "", 0, true},
		{"example.com:99999", "", 0, true},
	}
	for _, c := range cases {
		h, p, err := ParseTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): unexpected error %v", c.in, err)
			continue
		}
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("ParseTarget(%q) = %q,%d; want %q,%d", c.in, h, p, c.wantHost, c.wantPort)
		}
	}
}
