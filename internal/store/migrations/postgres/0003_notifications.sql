-- 0003_notifications (postgres): per-user notification channels.
CREATE TABLE IF NOT EXISTS notification_channels (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    thresholds  TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_channels_user ON notification_channels (user_id);
CREATE INDEX IF NOT EXISTS idx_channels_enabled ON notification_channels (enabled);
