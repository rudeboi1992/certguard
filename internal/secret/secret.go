// Package secret provides the encrypted secret vault. Design (envelope
// encryption):
//
//   - Secret values are sealed with a random 256-bit Data Key (DEK) using
//     AES-256-GCM.
//   - The DEK never touches disk in the clear. It is wrapped (encrypted) by a
//     Key-Encryption-Key (KEK) and only the wrapped form is stored (in the meta
//     table). The KEK is derived either from the operator key file / env
//     (auto-unlock mode) or from a passphrase the admin types (locked mode).
//
// In passphrase mode nothing on disk can decrypt the vault — the passphrase,
// held only in the admin's head and briefly in server memory after unlock, is
// required. Argon2id stretches the passphrase.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Box seals and opens secret values with a fixed 256-bit data key.
type Box struct{ gcm cipher.AEAD }

// NewBox builds a Box from a 32-byte data key.
func NewBox(key [32]byte) (*Box, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{gcm: gcm}, nil
}

// Seal encrypts plaintext and returns base64(nonce || ciphertext || tag).
func (b *Box) Seal(plaintext string) (string, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)), nil
}

// Open reverses Seal, failing on corruption or the wrong key.
func (b *Box) Open(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	pt, err := openGCM(b.gcm, raw)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// --- key material ---

// RandomKey returns a fresh 256-bit key.
func RandomKey() ([32]byte, error) {
	var k [32]byte
	_, err := io.ReadFull(rand.Reader, k[:])
	return k, err
}

// RandomSalt returns n random bytes (for Argon2).
func RandomSalt(n int) ([]byte, error) {
	s := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, s)
	return s, err
}

// KeyFromString derives a KEK from raw high-entropy material (the auto key file
// / env value) with SHA-256. Adequate because the input is already random.
func KeyFromString(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// KeyFromPassphrase derives a KEK from a human passphrase with Argon2id.
func KeyFromPassphrase(passphrase string, salt []byte) [32]byte {
	var k [32]byte
	dk := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	copy(k[:], dk)
	return k
}

// WrapKey encrypts a data key with a KEK, returning base64(nonce||ct||tag).
func WrapKey(dek, kek [32]byte) (string, error) {
	gcm, err := gcmFor(kek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, dek[:], nil)), nil
}

// UnwrapKey reverses WrapKey. A wrong KEK (e.g. wrong passphrase) fails the GCM
// tag check rather than returning garbage.
func UnwrapKey(wrapped string, kek [32]byte) ([32]byte, error) {
	var dek [32]byte
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return dek, err
	}
	gcm, err := gcmFor(kek)
	if err != nil {
		return dek, err
	}
	pt, err := openGCM(gcm, raw)
	if err != nil {
		return dek, err
	}
	if len(pt) != 32 {
		return dek, errors.New("unexpected data-key length")
	}
	copy(dek[:], pt)
	return dek, nil
}

func gcmFor(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func openGCM(gcm cipher.AEAD, raw []byte) ([]byte, error) {
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, errors.New("could not decrypt (wrong key/passphrase or corrupt data)")
	}
	return pt, nil
}

// Hint returns a masked last-4 display hint for a secret.
func Hint(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	tail := plaintext
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return "••" + tail
}

// LoadOrCreateKey returns the operator master-key material at path, generating a
// fresh random 32-byte key (hex) and persisting it (0600) if the file is missing
// or empty. Used to derive the auto-unlock KEK when no passphrase is set.
func LoadOrCreateKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if k := strings.TrimSpace(string(b)); k != "" {
			return k, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		return "", fmt.Errorf("write key file %s: %w", path, err)
	}
	return key, nil
}
