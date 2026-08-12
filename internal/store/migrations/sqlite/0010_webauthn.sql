-- Security keys (WebAuthn/FIDO2) as a second factor at sign-in, and as a way
-- to unlock the secret vault.
--
-- credential_id is the authenticator's own handle for the credential and is
-- globally unique, so it carries the UNIQUE constraint rather than an index on
-- (user_id, name) — the same physical key registered by two users is two rows
-- with two different credential IDs.
--
-- sign_count is the authenticator's replay counter. It is stored and compared
-- on every assertion; a counter that goes backwards means a cloned key. Many
-- modern authenticators pin it at 0, which the spec permits, so a zero counter
-- is not itself suspicious.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    credential_id  TEXT NOT NULL UNIQUE,   -- base64url
    public_key     TEXT NOT NULL,          -- base64url COSE key
    aaguid         TEXT NOT NULL DEFAULT '',
    sign_count     INTEGER NOT NULL DEFAULT 0,
    transports     TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state   INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL,
    last_used_at   TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- One wrapped copy of the vault data key per security key.
--
-- This is deliberately a SECOND wrapper, not a replacement: the same data key
-- is already wrapped under the passphrase, and both unwrap to the same thing.
-- A security key is therefore a faster door, never the only door — losing it
-- must not cost the operator every stored secret. The passphrase wrapper is
-- what makes that guarantee, so the API refuses to delete the last non-key
-- wrapper.
--
-- The wrapping happens in the browser from the WebAuthn prf extension output;
-- the server stores ciphertext it cannot open, exactly as it does for the
-- zero-knowledge passphrase keyring.
CREATE TABLE IF NOT EXISTS vault_key_wrappers (
    credential_id TEXT PRIMARY KEY,        -- FK to webauthn_credentials.credential_id
    wrapped       TEXT NOT NULL,           -- base64 IV||ciphertext of the data key
    prf_salt      TEXT NOT NULL,           -- base64 salt fed to the prf extension
    created_at    TEXT NOT NULL,
    FOREIGN KEY (credential_id) REFERENCES webauthn_credentials(credential_id) ON DELETE CASCADE
);
