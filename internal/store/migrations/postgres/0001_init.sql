-- 0001_init (postgres): core certs table.
-- Same schema as the SQLite variant; identity column and BIGINT keys are the
-- only dialect differences. Timestamps stay TEXT (RFC3339 UTC) for parity.
CREATE TABLE IF NOT EXISTS certs (
    id                       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    dns_names                TEXT    NOT NULL DEFAULT '',
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
