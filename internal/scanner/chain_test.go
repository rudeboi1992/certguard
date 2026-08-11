package scanner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// issue signs a certificate with parent (or itself when parent is nil).
func issue(t *testing.T, cn string, notAfter time.Time, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !isCA {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// serveChain starts a TLS listener presenting exactly the certificates given,
// leaf first, and returns its host and port.
func serveChain(t *testing.T, leafKey *rsa.PrivateKey, certs ...*x509.Certificate) (string, int) {
	t.Helper()
	raw := make([][]byte, len(certs))
	for i, c := range certs {
		raw[i] = c.Raw
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: leafKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the handshake, then drop it — we only want the certificates.
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				conn.Close()
			}()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestScanRecordsIntermediatesNotLeafOrRoot(t *testing.T) {
	root, rootKey := issue(t, "Test Root", time.Now().AddDate(10, 0, 0), true, nil, nil)
	interNotAfter := time.Now().AddDate(0, 0, 20).Truncate(time.Second)
	inter, interKey := issue(t, "Test Intermediate", interNotAfter, true, root, rootKey)
	leaf, leafKey := issue(t, "leaf.test", time.Now().AddDate(1, 0, 0), false, inter, interKey)

	// Servers commonly send the root too, even though they need not.
	host, port := serveChain(t, leafKey, leaf, inter, root)

	res, err := Scan(context.Background(), host, port, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.ChainLen != 3 {
		t.Errorf("ChainLen = %d, want 3 (leaf + intermediate + root)", res.ChainLen)
	}
	// The leaf is the Result itself and the root is self-issued, so only the
	// intermediate — the link a human might actually have to act on — is kept.
	if len(res.Chain) != 1 {
		t.Fatalf("Chain has %d entries, want 1: %+v", len(res.Chain), res.Chain)
	}
	got := res.Chain[0]
	if got.Subject != "CN=Test Intermediate" {
		t.Errorf("Chain[0].Subject = %q, want CN=Test Intermediate", got.Subject)
	}
	if !got.NotAfter.Equal(interNotAfter.UTC()) {
		t.Errorf("Chain[0].NotAfter = %s, want %s", got.NotAfter, interNotAfter.UTC())
	}
	if got.SHA256 == "" {
		t.Error("Chain[0].SHA256 is empty")
	}
}

func TestScanSelfSignedLeafHasNoChain(t *testing.T) {
	leaf, leafKey := issue(t, "solo.test", time.Now().AddDate(1, 0, 0), false, nil, nil)
	host, port := serveChain(t, leafKey, leaf)

	res, err := Scan(context.Background(), host, port, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Chain) != 0 {
		t.Errorf("Chain = %+v, want empty for a lone self-signed leaf", res.Chain)
	}
}
