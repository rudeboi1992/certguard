-- See the sqlite copy for why this exists.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    aaguid          TEXT NOT NULL DEFAULT '',
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

CREATE TABLE IF NOT EXISTS vault_key_wrappers (
    credential_id TEXT PRIMARY KEY REFERENCES webauthn_credentials(credential_id) ON DELETE CASCADE,
    wrapped       TEXT NOT NULL,
    prf_salt      TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
