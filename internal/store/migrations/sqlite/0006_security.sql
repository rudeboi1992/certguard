-- 0006_security: key-value meta table (holds the envelope-wrapped vault data
-- key + mode/salt) and per-user TOTP two-factor fields.
CREATE TABLE meta (
    mkey TEXT PRIMARY KEY,
    mval TEXT NOT NULL DEFAULT ''
);
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
