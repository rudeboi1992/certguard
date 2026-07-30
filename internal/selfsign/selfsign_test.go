package selfsign

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCertGeneratesUsablePair(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "c.pem")
	key := filepath.Join(dir, "k.pem")

	if err := EnsureCert(cert, key, "certguard.example.com,10.0.0.5", time.Now()); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	// The generated PEM pair must load as a valid TLS key pair.
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}

	// Idempotent: a second call must not overwrite existing files.
	before, _ := os.ReadFile(cert)
	if err := EnsureCert(cert, key, "other", time.Now()); err != nil {
		t.Fatalf("second EnsureCert: %v", err)
	}
	after, _ := os.ReadFile(cert)
	if string(before) != string(after) {
		t.Fatal("EnsureCert overwrote an existing certificate")
	}
}
