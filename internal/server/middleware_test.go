package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func reqFrom(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIPIgnoresForgedXFFByDefault(t *testing.T) {
	// The connection is from one address; the attacker forges a different
	// X-Forwarded-For on each request to try to escape the rate-limit bucket.
	// With no trusted proxy, every request must key on the real address.
	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		got := clientIP(reqFrom("203.0.113.9:5555", forged), false)
		if got != "203.0.113.9" {
			t.Errorf("clientIP with forged XFF %q = %q, want the real 203.0.113.9", forged, got)
		}
	}
}

func TestClientIPHonoursXFFWhenProxyTrusted(t *testing.T) {
	got := clientIP(reqFrom("10.0.0.1:5555", "198.51.100.7, 10.0.0.1"), true)
	if got != "198.51.100.7" {
		t.Errorf("clientIP behind trusted proxy = %q, want the first hop 198.51.100.7", got)
	}
}

func TestRateLimitCannotBeBypassedByForgingXFF(t *testing.T) {
	// End to end: a fixed connection address hammering the limiter with a
	// rotating forged header must still be throttled.
	rl := newRateLimiter(3, time.Minute)
	now := time.Now()
	blocked := false
	for i := 0; i < 10; i++ {
		ip := clientIP(reqFrom("203.0.113.9:5555", "9.9.9."+itoa(i)), false)
		if !rl.allow(ip, now) {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("rotating a forged X-Forwarded-For bypassed the rate limiter")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
