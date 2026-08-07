-- See the sqlite copy for why this exists and why it logs transitions rather
-- than every scan.
CREATE TABLE IF NOT EXISTS events (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at         TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    cert_id    BIGINT,
    cert_name  TEXT    NOT NULL DEFAULT '',
    actor      TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_at ON events (at DESC);
CREATE INDEX IF NOT EXISTS idx_events_cert ON events (cert_id);
