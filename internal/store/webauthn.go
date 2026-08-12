package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// ErrNoCredential is returned when a credential ID is not registered.
var ErrNoCredential = errors.New("credential not found")

const credCols = `SELECT c.id, c.user_id, c.credential_id, c.public_key, c.aaguid,
	c.sign_count, c.transports, c.name, c.backup_eligible, c.backup_state,
	c.created_at, c.last_used_at, c.prf_supported,
	CASE WHEN w.credential_id IS NULL THEN 0 ELSE 1 END AS unlocks_vault
	FROM webauthn_credentials c
	LEFT JOIN vault_key_wrappers w ON w.credential_id = c.credential_id`

func scanCredential(r rowScanner) (*model.WebAuthnCredential, error) {
	var (
		c          model.WebAuthnCredential
		backupElig int
		backupSt   int
		unlocks    int
		createdAt  string
		lastUsed   string
	)
	err := r.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AAGUID,
		&c.SignCount, &c.Transports, &c.Name, &backupElig, &backupSt,
		&createdAt, &lastUsed, &c.PRFSupported, &unlocks)
	if err != nil {
		return nil, err
	}
	c.BackupEligible = backupElig != 0
	c.BackupState = backupSt != 0
	c.UnlocksVault = unlocks != 0
	c.CreatedAt = parseTime(createdAt)
	if lastUsed != "" {
		t := parseTime(lastUsed)
		c.LastUsedAt = &t
	}
	return &c, nil
}

// AddCredential registers a new security key for a user.
func (s *Store) AddCredential(c *model.WebAuthnCredential) (int64, error) {
	return s.insertReturningID(`INSERT INTO webauthn_credentials
		(user_id, credential_id, public_key, aaguid, sign_count, transports, name,
		 backup_eligible, backup_state, created_at, prf_supported)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		c.UserID, c.CredentialID, c.PublicKey, c.AAGUID, c.SignCount, c.Transports,
		c.Name, boolInt(c.BackupEligible), boolInt(c.BackupState),
		time.Now().UTC().Format(rfc3339), c.PRFSupported)
}

// CredentialsForUser lists a user's registered keys, newest last.
func (s *Store) CredentialsForUser(userID int64) ([]*model.WebAuthnCredential, error) {
	rows, err := s.query(credCols+` WHERE c.user_id=? ORDER BY c.id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.WebAuthnCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CredentialByID looks up one credential by the authenticator's handle.
func (s *Store) CredentialByID(credentialID string) (*model.WebAuthnCredential, error) {
	c, err := scanCredential(s.queryRow(credCols+` WHERE c.credential_id=?`, credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoCredential
	}
	return c, err
}

// TouchCredential records a successful assertion: the authenticator's replay
// counter and when it was last used.
func (s *Store) TouchCredential(credentialID string, signCount uint32) error {
	_, err := s.exec(
		`UPDATE webauthn_credentials SET sign_count=?, last_used_at=? WHERE credential_id=?`,
		signCount, time.Now().UTC().Format(rfc3339), credentialID)
	return err
}

// RenameCredential sets the human label for a key.
func (s *Store) RenameCredential(id, userID int64, name string) error {
	_, err := s.exec(`UPDATE webauthn_credentials SET name=? WHERE id=? AND user_id=?`,
		name, id, userID)
	return err
}

// DeleteCredential removes a key. Scoped by user so one account cannot delete
// another's. The vault wrapper goes with it via ON DELETE CASCADE, which is
// safe because the passphrase wrapper is always present.
func (s *Store) DeleteCredential(id, userID int64) error {
	_, err := s.exec(`DELETE FROM webauthn_credentials WHERE id=? AND user_id=?`, id, userID)
	return err
}

// CountCredentials reports how many keys a user has registered.
func (s *Store) CountCredentials(userID int64) (int, error) {
	var n int
	err := s.queryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, userID).Scan(&n)
	return n, err
}

// --- vault key wrappers -----------------------------------------------------

// SetVaultWrapper stores the vault data key wrapped under a key derived from a
// security key's prf output. The server cannot open it, exactly as with the
// zero-knowledge passphrase keyring.
func (s *Store) SetVaultWrapper(credentialID, wrapped, prfSalt string) error {
	if _, err := s.exec(`DELETE FROM vault_key_wrappers WHERE credential_id=?`, credentialID); err != nil {
		return err
	}
	_, err := s.exec(`INSERT INTO vault_key_wrappers (credential_id, wrapped, prf_salt, created_at)
		VALUES (?,?,?,?)`, credentialID, wrapped, prfSalt, time.Now().UTC().Format(rfc3339))
	return err
}

// VaultWrapper returns the wrapped data key and prf salt for a credential.
func (s *Store) VaultWrapper(credentialID string) (wrapped, prfSalt string, err error) {
	err = s.queryRow(`SELECT wrapped, prf_salt FROM vault_key_wrappers WHERE credential_id=?`,
		credentialID).Scan(&wrapped, &prfSalt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNoCredential
	}
	return wrapped, prfSalt, err
}

// DeleteVaultWrapper drops a key's ability to unlock the vault without
// unregistering the key itself as a second factor.
func (s *Store) DeleteVaultWrapper(credentialID string) error {
	_, err := s.exec(`DELETE FROM vault_key_wrappers WHERE credential_id=?`, credentialID)
	return err
}

// ClearVaultWrappers removes every security-key wrapper. Called when the vault
// passphrase is changed or zero-knowledge mode is disabled, because the data
// key those wrappers hold no longer opens anything.
func (s *Store) ClearVaultWrappers() error {
	_, err := s.exec(`DELETE FROM vault_key_wrappers`)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
