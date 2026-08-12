package store

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bfalcher/certguard/internal/model"
)

func keyStore(t *testing.T) (*Store, int64) {
	t.Helper()
	st, err := Open("sqlite", filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	u, err := st.CreateUser("a@x.com", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	return st, u.ID
}

func addKey(t *testing.T, st *Store, userID int64, credID, name string) int64 {
	t.Helper()
	id, err := st.AddCredential(&model.WebAuthnCredential{
		UserID: userID, CredentialID: credID, PublicKey: "pk", Name: name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCredentialRoundTrip(t *testing.T) {
	st, uid := keyStore(t)
	addKey(t, st, uid, "cred-a", "YubiKey")

	creds, err := st.CredentialsForUser(uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d credentials, want 1", len(creds))
	}
	c := creds[0]
	if c.Name != "YubiKey" || c.CredentialID != "cred-a" {
		t.Errorf("credential did not round-trip: %+v", c)
	}
	// A key with no wrapper must not claim it can open the vault.
	if c.UnlocksVault {
		t.Error("UnlocksVault is true for a key that was never paired")
	}
	if n, _ := st.CountCredentials(uid); n != 1 {
		t.Errorf("CountCredentials = %d, want 1", n)
	}
}

func TestSignCountAdvances(t *testing.T) {
	st, uid := keyStore(t)
	addKey(t, st, uid, "cred-a", "key")
	if err := st.TouchCredential("cred-a", 42); err != nil {
		t.Fatal(err)
	}
	c, err := st.CredentialByID("cred-a")
	if err != nil {
		t.Fatal(err)
	}
	if c.SignCount != 42 {
		t.Errorf("SignCount = %d, want 42", c.SignCount)
	}
	if c.LastUsedAt == nil {
		t.Error("LastUsedAt not recorded on use")
	}
}

func TestVaultWrapperLifecycle(t *testing.T) {
	st, uid := keyStore(t)
	addKey(t, st, uid, "cred-a", "key")

	if err := st.SetVaultWrapper("cred-a", "wrapped-blob", "salt-blob"); err != nil {
		t.Fatal(err)
	}
	wrapped, salt, err := st.VaultWrapper("cred-a")
	if err != nil || wrapped != "wrapped-blob" || salt != "salt-blob" {
		t.Fatalf("VaultWrapper = %q,%q,%v", wrapped, salt, err)
	}
	// The join has to surface the pairing, since that is what the UI reads.
	creds, _ := st.CredentialsForUser(uid)
	if !creds[0].UnlocksVault {
		t.Error("UnlocksVault is false for a paired key")
	}

	// Re-pairing replaces rather than duplicating (credential_id is the PK).
	if err := st.SetVaultWrapper("cred-a", "wrapped-2", "salt-2"); err != nil {
		t.Fatal(err)
	}
	wrapped, _, _ = st.VaultWrapper("cred-a")
	if wrapped != "wrapped-2" {
		t.Errorf("wrapper after re-pair = %q, want wrapped-2", wrapped)
	}

	if err := st.DeleteVaultWrapper("cred-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.VaultWrapper("cred-a"); err == nil {
		t.Error("VaultWrapper still returns a row after delete")
	}
	// Unpairing must NOT unregister the key as a second factor.
	if n, _ := st.CountCredentials(uid); n != 1 {
		t.Errorf("CountCredentials = %d after unpair, want 1 — the key itself should survive", n)
	}
}

func TestClearVaultWrappersLeavesKeys(t *testing.T) {
	st, uid := keyStore(t)
	addKey(t, st, uid, "cred-a", "a")
	addKey(t, st, uid, "cred-b", "b")
	_ = st.SetVaultWrapper("cred-a", "w", "s")
	_ = st.SetVaultWrapper("cred-b", "w", "s")

	// Turning zero-knowledge on generates a new data key, so every wrapper
	// becomes meaningless — but the keys stay usable for signing in.
	if err := st.ClearVaultWrappers(); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountCredentials(uid); n != 2 {
		t.Errorf("CountCredentials = %d, want 2", n)
	}
	creds, _ := st.CredentialsForUser(uid)
	for _, c := range creds {
		if c.UnlocksVault {
			t.Errorf("%s still claims to unlock the vault after a key rotation", c.Name)
		}
	}
}

func TestDeleteCredentialIsScopedToOwner(t *testing.T) {
	st, uid := keyStore(t)
	other, err := st.CreateUser("b@x.com", "hash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	id := addKey(t, st, uid, "cred-a", "mine")

	// Another account must not be able to remove someone else's key.
	if err := st.DeleteCredential(id, other.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountCredentials(uid); n != 1 {
		t.Fatalf("another user deleted a key that was not theirs")
	}
	if err := st.DeleteCredential(id, uid); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountCredentials(uid); n != 0 {
		t.Errorf("owner could not delete their own key")
	}
}

func TestDeletingKeyCascadesItsWrapper(t *testing.T) {
	st, uid := keyStore(t)
	id := addKey(t, st, uid, "cred-a", "key")
	_ = st.SetVaultWrapper("cred-a", "w", "s")
	if err := st.DeleteCredential(id, uid); err != nil {
		t.Fatal(err)
	}
	// A wrapper naming a credential that no longer exists would be unreachable
	// clutter that the UnlocksVault join could still trip over.
	if _, _, err := st.VaultWrapper("cred-a"); err == nil {
		t.Error("wrapper survived deletion of its credential")
	}
}

func TestPRFSupportedTriState(t *testing.T) {
	st, uid := keyStore(t)

	// A row written before certguard asked about prf — exactly the state of a
	// key registered on an earlier version. It must read back as "unknown",
	// not as "cannot", or the UI would wrongly refuse to let the owner try.
	if _, err := st.exec(`INSERT INTO webauthn_credentials
		(user_id, credential_id, public_key, created_at) VALUES (?,?,?,?)`,
		uid, "legacy-cred", "pk", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	legacy, err := st.CredentialByID("legacy-cred")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.PRFSupported != -1 {
		t.Errorf("legacy credential PRFSupported = %d, want -1 (unknown)", legacy.PRFSupported)
	}

	for _, want := range []int{0, 1} {
		id := "cred-prf-" + strconv.Itoa(want)
		if _, err := st.AddCredential(&model.WebAuthnCredential{
			UserID: uid, CredentialID: id, PublicKey: "pk", PRFSupported: want,
		}); err != nil {
			t.Fatal(err)
		}
		got, err := st.CredentialByID(id)
		if err != nil {
			t.Fatal(err)
		}
		if got.PRFSupported != want {
			t.Errorf("PRFSupported = %d, want %d", got.PRFSupported, want)
		}
	}
}
