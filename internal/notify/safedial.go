package notify

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// safeControl rejects a connection whose resolved address is private, loopback,
// link-local, or otherwise not a normal public host.
//
// It runs as the Dialer's Control hook, which fires AFTER name resolution with
// the concrete IP the socket is about to connect to. Checking here rather than
// parsing the URL closes the DNS-rebinding hole: a hostname that resolves to a
// public IP at validation time but a private one at dial time is still caught,
// because this sees the address actually being dialed.
func safeControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("blocked: cannot parse dial address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("blocked: %q did not resolve to an IP", host)
	}
	if !isPublicIP(ip) {
		return fmt.Errorf("blocked: %s is a private, loopback, or link-local address; "+
			"set CERTGUARD_ALLOW_PRIVATE_WEBHOOKS=1 to allow internal notification targets", ip)
	}
	return nil
}

// isPublicIP reports whether ip is a routable public address — i.e. not one of
// the ranges an SSRF would target: loopback, RFC1918 / ULA private space,
// link-local (incl. the 169.254.169.254 cloud metadata endpoint), the
// unspecified address, and multicast.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	// IsPrivate covers fc00::/7 and the RFC1918 blocks; catch a few ranges the
	// stdlib does not treat as "private" but which are equally not public.
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 127: // redundant with IsLoopback, kept explicit
			return false
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT
			return false
		case ip4[0] == 0: // 0.0.0.0/8 "this network"
			return false
		}
	}
	return true
}

// safeHTTPTransport builds an http transport whose dialer refuses non-public
// addresses, unless the operator has opted into private targets.
func safeHTTPTransport(allowPrivate bool) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		d.Control = safeControl
	}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		// A redirect could point back at an internal address, but each redirect
		// re-dials through the same Control hook, so it is covered too.
		MaxIdleConns: 10,
	}
}
