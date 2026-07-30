package secret

import "testing"

func TestBoxRoundTrip(t *testing.T) {
	dek, _ := RandomKey()
	box, err := NewBox(dek)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	for _, pt := range []string{"", "sk-abc123", "-----BEGIN KEY-----\nx\n-----END KEY-----"} {
		enc, err := box.Seal(pt)
		if err != nil {
			t.Fatalf("Seal(%q): %v", pt, err)
		}
		if enc == pt && pt != "" {
			t.Fatalf("ciphertext equals plaintext for %q", pt)
		}
		got, err := box.Open(enc)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != pt {
			t.Fatalf("round trip: got %q want %q", got, pt)
		}
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	dek, _ := RandomKey()
	kek := KeyFromString("master-key-material")
	wrapped, err := WrapKey(dek, kek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(wrapped, kek)
	if err != nil || got != dek {
		t.Fatalf("UnwrapKey round trip failed: %v", err)
	}
	// Wrong KEK must fail the tag check, not return garbage.
	if _, err := UnwrapKey(wrapped, KeyFromString("wrong")); err == nil {
		t.Fatal("expected unwrap with wrong KEK to fail")
	}
}

func TestPassphraseKEK(t *testing.T) {
	salt, _ := RandomSalt(16)
	k1 := KeyFromPassphrase("correct horse battery staple", salt)
	k2 := KeyFromPassphrase("correct horse battery staple", salt)
	if k1 != k2 {
		t.Fatal("Argon2id not deterministic for same passphrase+salt")
	}
	if KeyFromPassphrase("different", salt) == k1 {
		t.Fatal("different passphrases yielded the same key")
	}
	// Full envelope: wrap a DEK under a passphrase-KEK, wrong passphrase fails.
	dek, _ := RandomKey()
	wrapped, _ := WrapKey(dek, k1)
	if got, _ := UnwrapKey(wrapped, k2); got != dek {
		t.Fatal("unwrap with correct passphrase failed")
	}
	if _, err := UnwrapKey(wrapped, KeyFromPassphrase("nope", salt)); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestHint(t *testing.T) {
	if got := Hint("ghp_abcdWXYZ"); got != "••WXYZ" {
		t.Fatalf("Hint = %q", got)
	}
	if got := Hint(""); got != "" {
		t.Fatalf("empty Hint = %q", got)
	}
}
