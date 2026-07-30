// Package secret provides authenticated symmetric encryption for the optional
// secret vault: an entry can store its actual secret value (API key, token,
// private key) encrypted at rest with AES-256-GCM. The AES key is derived from
// the operator-supplied CERTGUARD_MASTER_KEY, which is never persisted — only
// ciphertext ever touches the database.
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
)

// LoadOrCreateKey returns the master-key material stored at path, generating a
// fresh random 32-byte key (hex) and persisting it (0600) if the file is missing
// or empty. This lets the secret vault work with zero setup — the operator never
// has to run anything. A write failure is returned so the caller can leave the
// vault disabled rather than use a key that won't survive a restart.
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

// Box seals and opens secret values with a fixed 256-bit key.
type Box struct{ gcm cipher.AEAD }

// New derives a Box from the master key string. Any non-empty input works
// (hex, base64, or a passphrase) — it is hashed to a 32-byte AES key, so the
// security rests on the entropy of the input (use `openssl rand -hex 32`).
// Returns nil when masterKey is empty (vault disabled).
func New(masterKey string) (*Box, error) {
	if masterKey == "" {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(masterKey))
	block, err := aes.NewCipher(sum[:])
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
	ct := b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal. It fails if the data is corrupt or the key is wrong
// (e.g. the master key changed), rather than returning garbage.
func (b *Box) Open(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	ns := b.gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := b.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", errors.New("could not decrypt (wrong master key or corrupt data)")
	}
	return string(pt), nil
}

// Hint returns a low-sensitivity display hint for a secret: a masked last-4.
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
