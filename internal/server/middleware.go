package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Content-Security-Policy for the UI. Scripts and styles are same-origin only;
// no inline scripts are allowed (the theme snippet lives in /static/theme-init.js),
// which is the primary defence-in-depth against XSS. Inline *style attributes*
// (used for widget sizing) are permitted via 'unsafe-inline' in style-src — a low
// risk. data: images cover the inline SVG favicon and the 2FA QR.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// securityHeaders wraps a handler with a standard set of hardening response
// headers applied to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		// HSTS only makes sense (and is only honoured) over HTTPS. r.TLS covers
		// direct TLS; the forwarded header covers termination at a reverse proxy.
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a small in-memory sliding-window limiter keyed by client IP,
// used to slow credential guessing on the auth endpoints. It is best-effort and
// per-process (not shared across replicas), which is the right layer for a
// single self-hosted instance.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{hits: make(map[string][]time.Time), max: max, window: window}
	return rl
}

// allow records an attempt for key and reports whether it is under the limit.
// It also prunes expired entries for that key, keeping the map bounded to
// recently-active clients.
func (rl *rateLimiter) allow(key string, now time.Time) bool {
	cutoff := now.Add(-rl.window)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.max {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// clientIP extracts the caller's IP for rate-limiting. It honours the first hop
// of X-Forwarded-For when present (the app is commonly run behind a reverse
// proxy), else falls back to the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := indexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return trimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limitAuth rate-limits an auth handler by client IP, returning 429 with a
// Retry-After hint once the window is exhausted.
func (s *Server) limitAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.loginLimiter.allow(clientIP(r), time.Now()) {
			w.Header().Set("Retry-After", strconv.Itoa(int(s.loginLimiter.window.Seconds())))
			writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
			return
		}
		next(w, r)
	}
}

// small dependency-free string helpers (avoid importing strings just for these).
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
