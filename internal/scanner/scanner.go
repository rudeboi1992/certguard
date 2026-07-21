// Package scanner performs active TLS certificate inspection.
//
// Unlike the original ExpiryGuard, which required a human to type in expiry
// dates or drag files one at a time, this connects to a live host:port over
// TLS and reads the leaf certificate directly. It deliberately completes the
// handshake even when the certificate is expired, self-signed, or otherwise
// untrusted, so that those are exactly the cases we can report on.
package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultPort is used when a target is given without an explicit port.
const DefaultPort = 443

// DefaultTimeout bounds the whole dial + handshake.
const DefaultTimeout = 10 * time.Second

// Options tunes a scan.
type Options struct {
	// Timeout bounds dial + handshake. Zero means DefaultTimeout.
	Timeout time.Duration
	// ServerName overrides the SNI sent in the handshake. Empty means use the
	// dialed host. Set this when the host is an IP but you want a named vhost.
	ServerName string
}

// Result is the flattened, storable view of a scanned leaf certificate.
type Result struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	ServerName string    `json:"server_name"`
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	SHA256     string    `json:"sha256"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names"`
	KeyType    string    `json:"key_type"`
	SigAlg     string    `json:"signature_algorithm"`
	IsCA       bool      `json:"is_ca"`
	ChainLen   int       `json:"chain_length"`
	// TrustError is the verification error observed during the handshake, if
	// any (expired, self-signed, hostname mismatch). Empty means the chain
	// verified against the system roots. The scan still succeeds either way —
	// this is data, not a failure.
	TrustError string `json:"trust_error,omitempty"`
}

// DaysUntilExpiry reports whole days from now until NotAfter (may be negative).
func (r *Result) DaysUntilExpiry(now time.Time) int {
	return int(r.NotAfter.Sub(now).Hours() / 24)
}

// Scan connects to host:port, completes a TLS handshake, and returns the leaf
// certificate's details. A returned error means we could not obtain a
// certificate at all (connection refused, timeout, non-TLS port). An expired
// or untrusted certificate is NOT an error — it comes back in Result.TrustError.
func Scan(ctx context.Context, host string, port int, opts Options) (*Result, error) {
	if port == 0 {
		port = DefaultPort
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	// InsecureSkipVerify lets the handshake complete for expired/self-signed
	// certs so we can still read them; we recover the real trust verdict
	// ourselves below via VerifyConnection.
	var trustErr string
	conf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			trustErr = verifyChain(cs, serverName)
			return nil // never abort — we want the cert regardless
		},
	}

	tlsConn := tls.Client(rawConn, conf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%s presented no certificates", addr)
	}
	leaf := state.PeerCertificates[0]

	return &Result{
		Host:       host,
		Port:       port,
		ServerName: serverName,
		Subject:    leaf.Subject.String(),
		Issuer:     leaf.Issuer.String(),
		Serial:     leaf.SerialNumber.String(),
		SHA256:     fingerprint(leaf),
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		DNSNames:   leaf.DNSNames,
		KeyType:    keyType(leaf),
		SigAlg:     leaf.SignatureAlgorithm.String(),
		IsCA:       leaf.IsCA,
		ChainLen:   len(state.PeerCertificates),
		TrustError: trustErr,
	}, nil
}

// verifyChain re-runs standard verification against system roots and returns a
// human-readable reason string when the chain does not verify.
func verifyChain(cs tls.ConnectionState, serverName string) string {
	if len(cs.PeerCertificates) == 0 {
		return "no certificate presented"
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return err.Error()
	}
	return ""
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func keyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// ParseTarget splits a "host", "host:port", or "https://host:port/..." style
// target into host and port, defaulting the port to DefaultPort.
func ParseTarget(target string) (host string, port int, err error) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if i := strings.IndexAny(target, "/"); i >= 0 {
		target = target[:i]
	}
	if target == "" {
		return "", 0, fmt.Errorf("empty target")
	}
	h, p, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		// No port present.
		return target, DefaultPort, nil
	}
	var pn int
	if _, scanErr := fmt.Sscanf(p, "%d", &pn); scanErr != nil || pn <= 0 || pn > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, pn, nil
}
