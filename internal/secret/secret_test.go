package secret

import "testing"

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := New("test-master-key-with-plenty-of-entropy")
	if err != nil || box == nil {
		t.Fatalf("New: %v", err)
	}
	for _, pt := range []string{"", "sk-abc123", "-----BEGIN KEY-----\nline\n-----END KEY-----"} {
		enc, err := box.Seal(pt)
		if err != nil {
			t.Fatalf("Seal(%q): %v", pt, err)
		}
		if enc == pt {
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

func TestOpenWrongKeyFails(t *testing.T) {
	a, _ := New("key-a")
	b, _ := New("key-b")
	enc, _ := a.Seal("secret")
	if _, err := b.Open(enc); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestDisabledWhenEmpty(t *testing.T) {
	box, err := New("")
	if err != nil || box != nil {
		t.Fatalf("empty master key should yield a nil box, got %v %v", box, err)
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
