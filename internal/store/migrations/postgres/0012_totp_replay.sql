-- See the sqlite copy for why this exists.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
