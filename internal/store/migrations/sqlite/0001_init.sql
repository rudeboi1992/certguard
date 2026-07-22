-- 0001_init: core certs table.
-- Phase 1 targets SQLite. Timestamps are stored as TEXT (RFC3339 UTC) to keep
-- date handling explicit and driver-independent. Postgres support (Phase 2)
-- will supply a dialect-adjusted copy of these migrations (SERIAL, etc.).
CREATE TABLE IF NOT EXISTS certs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT    NOT NULL,
    kind                     TEXT    NOT NULL DEFAULT 'manual',

    host                     TEXT    NOT NULL DEFAULT '',
    port                     INTEGER NOT NULL DEFAULT 0,
    server_name              TEXT    NOT NULL DEFAULT '',

    subject                  TEXT    NOT NULL DEFAULT '',
    issuer                   TEXT    NOT NULL DEFAULT '',
    serial                   TEXT    NOT NULL DEFAULT '',
    sha256                   TEXT    NOT NULL DEFAULT '',
    not_before               TEXT    NOT NULL DEFAULT '',
    expires_at               TEXT    NOT NULL,
    dns_names                TEXT    NOT NULL DEFAULT '',   -- JSON array
    key_type                 TEXT    NOT NULL DEFAULT '',
    sig_alg                  TEXT    NOT NULL DEFAULT '',

    auto_rescan              INTEGER NOT NULL DEFAULT 1,
    last_scanned_at          TEXT,
    last_error               TEXT    NOT NULL DEFAULT '',
    notes                    TEXT    NOT NULL DEFAULT '',
    active                   INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT    NOT NULL,

    last_notified_threshold  INTEGER NOT NULL DEFAULT 0,
    last_notified_on         TEXT
);

CREATE INDEX IF NOT EXISTS idx_certs_active_expiry ON certs (active, expires_at);
CREATE INDEX IF NOT EXISTS idx_certs_sha256 ON certs (sha256);
