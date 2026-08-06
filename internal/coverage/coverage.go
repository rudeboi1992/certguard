// Package coverage answers "which certificate actually serves each name this
// one covers".
package coverage

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/scanner"
)

// Check connects to every name a certificate covers and reports the
// certificate each one actually serves.
//
// A SAN list says what a certificate is valid FOR, not what is deployed. One
// host can serve a different certificate per vhost via SNI, and two
// certificates may legitimately cover the same name — so a name being listed
// here is no guarantee that this is the certificate answering for it. That gap
// is invisible from the entry alone and is exactly what this checks.
//
// It lives in its own package so both the HTTP handler and the unattended
// scheduler can run it without an import cycle.
func Check(ctx context.Context, c *model.Cert, timeout time.Duration) ([]model.CoveredName, int) {
	port := c.Port
	if port == 0 {
		port = scanner.DefaultPort
	}
	out := make([]model.CoveredName, len(c.DNSNames))
	sem := make(chan struct{}, 6) // bounded: a wildcard cert can carry many names
	var wg sync.WaitGroup

	for i, name := range c.DNSNames {
		// A wildcard is not a host — there is nothing to connect to. Report it
		// rather than dropping it, so the list still adds up against the SANs.
		if strings.HasPrefix(name, "*.") {
			out[i] = model.CoveredName{Name: name, Status: "wildcard",
				Detail: "not a hostname — nothing to connect to"}
			continue
		}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := scanner.Scan(ctx, name, port, scanner.Options{Timeout: timeout})
			if err != nil {
				out[i] = model.CoveredName{Name: name, Status: "unreachable", Detail: err.Error()}
				return
			}
			status := "different"
			if res.SHA256 == c.SHA256 {
				status = "match"
			}
			out[i] = model.CoveredName{Name: name, Status: status,
				Subject: res.Subject, SHA256: res.SHA256}
		}(i, name)
	}
	wg.Wait()
	return out, port
}
