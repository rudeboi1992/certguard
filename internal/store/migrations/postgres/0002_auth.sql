-- 0002_auth (postgres): users, API tokens, sessions.
CREATE TABLE IF NOT EXISTS users (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email          TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,
    role           TEXT    NOT NULL DEFAULT 'viewer',
    created_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL DEFAULT '',
    token_hash    TEXT    NOT NULL UNIQUE,
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash  TEXT    NOT NULL UNIQUE,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions (session_hash);
