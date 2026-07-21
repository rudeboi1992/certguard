-- 0002_auth: users, API tokens, and sessions.
-- Users are admin-provisioned via the CLI; there is no public registration.
-- Tokens and sessions store only a SHA-256 hash of the secret, never plaintext.
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    email          TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,
    role           TEXT    NOT NULL DEFAULT 'viewer',
    created_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL DEFAULT '',
    token_hash    TEXT    NOT NULL UNIQUE,
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash  TEXT    NOT NULL UNIQUE,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions (session_hash);
