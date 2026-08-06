package server

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/bfalcher/certguard/internal/rdap"
)

// rdapCache memoises registry lookups for a short window.
//
// Without it the discovery flow queries every domain twice: once to offer it,
// once to store it when the user accepts. Registries — and rdap.org, which is
// run as a courtesy — rate-limit, and a certificate with a dozen SANs turns
// into two dozen requests in a few seconds, at which point the adds start
// failing. Registration dates move once a year, so a few minutes of staleness
// costs nothing.
type rdapCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*rdapEntry
}

type rdapEntry struct {
	res  *rdap.Result
	err  error
	when time.Time
}

func newRDAPCache(ttl time.Duration) *rdapCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &rdapCache{ttl: ttl, m: map[string]*rdapEntry{}}
}

// Lookup returns a cached result when one is fresh. force skips the cache, for
// the explicit "refresh now" button — a user who just renewed should not be
// told the old date.
//
// Failures are cached too, and deliberately: a domain that is not registered,
// or a ccTLD that publishes no expiry, will answer the same way for the whole
// window, and retrying it on every request is exactly the traffic that gets a
// client throttled.
func (c *rdapCache) Lookup(ctx context.Context, host string, timeout time.Duration, force bool) (*rdap.Result, error) {
	key, err := rdap.Registrable(host)
	if err != nil {
		return nil, err
	}
	key = strings.ToLower(key)

	if !force {
		c.mu.Lock()
		e, ok := c.m[key]
		c.mu.Unlock()
		if ok && time.Since(e.when) < c.ttl {
			return e.res, e.err
		}
	}

	res, err := rdap.Lookup(ctx, key, rdap.Options{Timeout: timeout})

	c.mu.Lock()
	c.m[key] = &rdapEntry{res: res, err: err, when: time.Now()}
	// The map only ever holds domains someone asked about; bound it anyway so a
	// long-running process cannot grow it without limit.
	if len(c.m) > 512 {
		for k, v := range c.m {
			if time.Since(v.when) >= c.ttl {
				delete(c.m, k)
			}
		}
	}
	c.mu.Unlock()
	return res, err
}
