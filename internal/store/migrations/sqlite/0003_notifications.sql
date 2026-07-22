-- 0003_notifications: per-user notification channels.
-- The cert inventory is shared, so a channel alerts its owner about any cert
-- crossing one of its thresholds. thresholds is a CSV like '30,7,3' (empty=all).
CREATE TABLE IF NOT EXISTS notification_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    thresholds  TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channels_user ON notification_channels (user_id);
CREATE INDEX IF NOT EXISTS idx_channels_enabled ON notification_channels (enabled);
