-- 0008_events: an activity log, so "when did this change, and why" has an
-- answer after the fact.
--
-- Deliberately not a row per scan. The scheduler re-scans every tracked
-- endpoint every 6 hours; logging each one would add thousands of rows a week
-- that all say "still fine", and bury the handful that matter. Only
-- transitions are recorded — a scan that starts failing, one that recovers, a
-- certificate that was replaced — plus the things a person did.
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT    NOT NULL,             -- RFC3339 UTC, as everywhere else
    kind       TEXT    NOT NULL,             -- added | updated | deleted | renewed | scan_failed | scan_recovered | coverage | notified
    cert_id    INTEGER,                      -- kept nullable, and NOT a foreign key:
                                             -- the log has to outlive the entry it describes
    cert_name  TEXT    NOT NULL DEFAULT '',  -- denormalised for the same reason
    actor      TEXT    NOT NULL DEFAULT '',  -- user email, or '' for the scheduler
    detail     TEXT    NOT NULL DEFAULT ''
);

-- The page reads newest-first, optionally filtered by kind.
CREATE INDEX IF NOT EXISTS idx_events_at ON events (at DESC);
CREATE INDEX IF NOT EXISTS idx_events_cert ON events (cert_id);
