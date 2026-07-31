package server

import (
	"encoding/base64"
	"errors"
	"os"
	"sync"

	"github.com/bfalcher/certguard/internal/secret"
	"github.com/bfalcher/certguard/internal/store"
)

// Meta keys for the vault keyring.
const (
	metaWrapped = "vault.wrapped" // wrapped data key (base64)
	metaSalt    = "vault.salt"    // Argon2 salt (base64), passphrase mode only
	metaMode    = "vault.mode"    // "auto" | "passphrase"

	// Zero-knowledge mode: the browser holds the only key. The server stores the
	// client-produced wrapped key + KDF params and never decrypts anything.
	metaZKWrapped = "zk.wrapped"
	metaZKSalt    = "zk.salt"
	metaZKIters   = "zk.iters"
)

var errVaultLocked = errors.New("vault is locked")

// vault manages the envelope-encrypted secret data key. In "auto" mode the data
// key is unwrapped with the operator key file/env on startup (transparent). In
// "passphrase" mode it stays locked until an admin unlocks it with the passphrase
// — so nothing on disk can decrypt the secrets.
type vault struct {
	store   *store.Store
	keyFile string

	mu      sync.RWMutex
	enabled bool
	zk      bool // zero-knowledge: all crypto is client-side; server has no key
	mode    string
	salt    []byte
	wrapped string
	dek     [32]byte // valid only while unlocked (non-ZK)
	box     *secret.Box
}

// newVault loads or bootstraps the keyring. masterMaterial is the resolved
// operator key (env), or "" to fall back to the key file.
func newVault(st *store.Store, masterMaterial, keyFile string) *vault {
	v := &vault{store: st, keyFile: keyFile}

	// Zero-knowledge mode: the server never holds a key; all crypto is client-side.
	if zk, err := st.GetMeta(metaZKWrapped); err == nil && zk != "" {
		v.enabled, v.zk = true, true
		return v
	}

	if wrapped, err := st.GetMeta(metaWrapped); err == nil && wrapped != "" {
		v.enabled = true
		v.wrapped = wrapped
		v.mode, _ = st.GetMeta(metaMode)
		if s, _ := st.GetMeta(metaSalt); s != "" {
			v.salt, _ = base64.StdEncoding.DecodeString(s)
		}
		if v.mode == modeAuto {
			material := masterMaterial
			if material == "" {
				material, _ = secret.LoadOrCreateKey(keyFile)
			}
			if material != "" {
				if dek, e := secret.UnwrapKey(v.wrapped, secret.KeyFromString(material)); e == nil {
					v.setUnlocked(dek)
				}
			}
		}
		return v // passphrase mode: stays locked until unlock()
	}

	// First run (or migrating a pre-keyring install): bootstrap in auto mode.
	material := masterMaterial
	if material == "" {
		if m, err := secret.LoadOrCreateKey(keyFile); err == nil {
			material = m
		}
	}
	if material == "" {
		return v // no key available → vault disabled
	}
	// DEK = KeyFromString(material) so any pre-existing secrets (sealed with that
	// derived key by the old code path) stay valid without re-encryption.
	dek := secret.KeyFromString(material)
	wrapped, err := secret.WrapKey(dek, dek)
	if err != nil {
		return v
	}
	_ = st.SetMeta(metaMode, modeAuto)
	_ = st.SetMeta(metaSalt, "")
	_ = st.SetMeta(metaWrapped, wrapped)
	v.enabled, v.mode, v.wrapped = true, modeAuto, wrapped
	v.setUnlocked(dek)
	return v
}

const (
	modeAuto       = "auto"
	modePassphrase = "passphrase"
)

func (v *vault) setUnlocked(dek [32]byte) {
	v.dek = dek
	v.box, _ = secret.NewBox(dek)
}

func (v *vault) statusEnabled() bool { v.mu.RLock(); defer v.mu.RUnlock(); return v.enabled }
func (v *vault) isUnlocked() bool    { v.mu.RLock(); defer v.mu.RUnlock(); return v.box != nil }

func (v *vault) status() (enabled, unlocked, passphrase bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.enabled, v.box != nil, v.mode == modePassphrase
}

// seal/open proxy to the box, erroring when locked.
func (v *vault) seal(pt string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.box == nil {
		return "", errVaultLocked
	}
	return v.box.Seal(pt)
}
func (v *vault) open(ct string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.box == nil {
		return "", errVaultLocked
	}
	return v.box.Open(ct)
}

// unlock derives the KEK from the passphrase and unwraps the data key.
func (v *vault) unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.enabled {
		return errors.New("vault not enabled")
	}
	if v.box != nil {
		return nil // already unlocked
	}
	if v.mode != modePassphrase {
		return errors.New("vault auto-unlocks; no passphrase set")
	}
	dek, err := secret.UnwrapKey(v.wrapped, secret.KeyFromPassphrase(passphrase, v.salt))
	if err != nil {
		return errors.New("incorrect passphrase")
	}
	v.setUnlocked(dek)
	return nil
}

func (v *vault) lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dek = [32]byte{}
	v.box = nil
}

// setPassphrase switches to passphrase mode (or changes the passphrase). The
// vault must be unlocked. Passing an empty newPass reverts to auto mode.
func (v *vault) setPassphrase(currentPass, newPass string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.box == nil {
		return errVaultLocked
	}
	// Changing an existing passphrase requires proving the current one.
	if v.mode == modePassphrase && newPass != "" {
		if _, err := secret.UnwrapKey(v.wrapped, secret.KeyFromPassphrase(currentPass, v.salt)); err != nil {
			return errors.New("current passphrase is incorrect")
		}
	}

	if newPass == "" {
		// Revert to auto mode: re-wrap under a fresh key-file key.
		material, err := secret.LoadOrCreateKey(v.keyFile)
		if err != nil {
			return err
		}
		wrapped, err := secret.WrapKey(v.dek, secret.KeyFromString(material))
		if err != nil {
			return err
		}
		if err := v.persist(modeAuto, nil, wrapped); err != nil {
			return err
		}
		return nil
	}

	salt, err := secret.RandomSalt(16)
	if err != nil {
		return err
	}
	wrapped, err := secret.WrapKey(v.dek, secret.KeyFromPassphrase(newPass, salt))
	if err != nil {
		return err
	}
	if err := v.persist(modePassphrase, salt, wrapped); err != nil {
		return err
	}
	// Remove the on-disk key so only the passphrase can unwrap the vault.
	_ = os.Remove(v.keyFile)
	return nil
}

func (v *vault) zkOn() bool { v.mu.RLock(); defer v.mu.RUnlock(); return v.zk }

// enableZK switches to zero-knowledge mode: store the client-produced keyring
// and drop all server-side key material so the server can no longer decrypt.
func (v *vault) enableZK(wrapped, salt, iters string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.store.SetMeta(metaZKWrapped, wrapped); err != nil {
		return err
	}
	_ = v.store.SetMeta(metaZKSalt, salt)
	_ = v.store.SetMeta(metaZKIters, iters)
	_ = v.store.SetMeta(metaWrapped, "")
	_ = v.store.SetMeta(metaMode, "")
	_ = v.store.SetMeta(metaSalt, "")
	_ = os.Remove(v.keyFile)
	v.enabled, v.zk = true, true
	v.dek = [32]byte{}
	v.box = nil
	return nil
}

func (v *vault) zkKeyring() (wrapped, salt, iters string) {
	wrapped, _ = v.store.GetMeta(metaZKWrapped)
	salt, _ = v.store.GetMeta(metaZKSalt)
	iters, _ = v.store.GetMeta(metaZKIters)
	return
}

// disableZK leaves zero-knowledge mode. Old ciphertext is unreadable server-side
// so all secrets are wiped, and the auto server keyring is re-bootstrapped.
func (v *vault) disableZK() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_ = v.store.SetMeta(metaZKWrapped, "")
	_ = v.store.SetMeta(metaZKSalt, "")
	_ = v.store.SetMeta(metaZKIters, "")
	_ = v.store.ClearAllSecrets()
	v.zk = false
	material, err := secret.LoadOrCreateKey(v.keyFile)
	if err != nil {
		v.enabled = false
		return err
	}
	dek := secret.KeyFromString(material)
	wrapped, err := secret.WrapKey(dek, dek)
	if err != nil {
		return err
	}
	_ = v.store.SetMeta(metaMode, modeAuto)
	_ = v.store.SetMeta(metaSalt, "")
	_ = v.store.SetMeta(metaWrapped, wrapped)
	v.mode, v.wrapped, v.enabled = modeAuto, wrapped, true
	v.setUnlocked(dek)
	return nil
}

func (v *vault) persist(mode string, salt []byte, wrapped string) error {
	saltB64 := ""
	if salt != nil {
		saltB64 = base64.StdEncoding.EncodeToString(salt)
	}
	if err := v.store.SetMeta(metaMode, mode); err != nil {
		return err
	}
	if err := v.store.SetMeta(metaSalt, saltB64); err != nil {
		return err
	}
	if err := v.store.SetMeta(metaWrapped, wrapped); err != nil {
		return err
	}
	v.mode, v.salt, v.wrapped = mode, salt, wrapped
	return nil
}
