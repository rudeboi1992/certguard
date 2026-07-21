package auth

import "testing"

func TestPasswordHashing(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("expected error for too-short password")
	}
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword(hash, "correct horse battery") {
		t.Error("CheckPassword rejected the correct password")
	}
	if CheckPassword(hash, "wrong password here") {
		t.Error("CheckPassword accepted a wrong password")
	}
}

func TestTokensAreUniqueAndHashed(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated tokens collided")
	}
	if a[:len(TokenPrefix)] != TokenPrefix {
		t.Errorf("token missing prefix: %q", a)
	}
	if HashSecret(a) == a {
		t.Error("HashSecret returned the plaintext")
	}
	if len(HashSecret(a)) != 64 {
		t.Errorf("expected 64-hex-char sha256, got %d chars", len(HashSecret(a)))
	}
	if !SecretsEqual(HashSecret(a), HashSecret(a)) {
		t.Error("SecretsEqual said identical hashes differ")
	}
	if SecretsEqual(HashSecret(a), HashSecret(b)) {
		t.Error("SecretsEqual said different hashes match")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc123":  "abc123",
		"bearer xyz":     "xyz",
		"Basic foo":      "",
		"":               "",
		"Bearer ":        "",
		"Bearer  spaced": "spaced",
	}
	for header, want := range cases {
		if got := BearerToken(header); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestRoleValid(t *testing.T) {
	if !RoleAdmin.Valid() || !RoleViewer.Valid() {
		t.Error("known roles should be valid")
	}
	if Role("superuser").Valid() {
		t.Error("unknown role should be invalid")
	}
}
