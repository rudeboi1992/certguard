// Package twofa implements TOTP (RFC 6238) two-factor codes: a random shared
// secret, 6-digit time-based codes on a 30-second step, and an otpauth:// URI
// for authenticator apps. No external dependencies.
package twofa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30 // seconds
)

// GenerateSecret returns a fresh 160-bit base32 secret (unpadded).
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="), nil
}

// Validate reports whether input is a valid code for secret now, tolerating one
// step of clock skew on either side.
func Validate(secret, input string) bool {
	_, ok := ValidateStep(secret, input, time.Now())
	return ok
}

// ValidateStep reports whether input matches the secret near now, and if so
// which counter step it matched. The step lets a caller reject replays: a code
// already consumed at a given step must not be accepted again.
//
// The ±1 window is walked from oldest to newest so that, when more than one
// step would match (they never do for distinct codes, but the loop must pick
// deterministically), the earliest is returned — consuming it advances the
// replay floor the least, which is the conservative choice.
func ValidateStep(secret, input string, now time.Time) (int64, bool) {
	input = strings.TrimSpace(input)
	if len(input) != digits {
		return 0, false
	}
	step := now.Unix() / period
	for _, d := range []int64{-1, 0, 1} {
		s := step + d
		if c, err := codeAt(secret, uint64(s)); err == nil && hmac.Equal([]byte(c), []byte(input)) {
			return s, true
		}
	}
	return 0, false
}

// Code returns the TOTP code for secret at time t. Useful for generating a
// current code (for display, or in tests) rather than only validating one.
func Code(secret string, t time.Time) (string, error) {
	return codeAt(secret, uint64(t.Unix()/period))
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans/imports.
func ProvisioningURI(secret, account, issuer string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(period))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

func codeAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(pad(secret))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, val%mod), nil
}

func pad(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if m := len(s) % 8; m != 0 {
		s += strings.Repeat("=", 8-m)
	}
	return s
}
