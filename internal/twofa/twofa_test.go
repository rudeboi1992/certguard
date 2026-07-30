package twofa

import (
	"testing"
	"time"
)

func TestValidateAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	step := uint64(time.Now().Unix() / period)
	code, err := codeAt(secret, step)
	if err != nil {
		t.Fatalf("codeAt: %v", err)
	}
	if !Validate(secret, code) {
		t.Fatal("current code rejected")
	}
	if Validate(secret, "000000") && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	if Validate(secret, "12345") { // wrong length
		t.Fatal("short code accepted")
	}
}

// RFC 6238 test vector (SHA-1, secret "12345678901234567890" base32) at T=59.
func TestKnownVector(t *testing.T) {
	// base32 of ASCII "12345678901234567890"
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := codeAt(secret, 1) // 59 / 30 = 1
	if err != nil {
		t.Fatalf("codeAt: %v", err)
	}
	if got != "287082" {
		t.Fatalf("RFC 6238 T1 = %q, want 287082", got)
	}
}
