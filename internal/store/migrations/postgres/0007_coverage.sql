-- See the sqlite copy for why this exists.
ALTER TABLE certs ADD COLUMN IF NOT EXISTS coverage_json TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN IF NOT EXISTS coverage_at TEXT NOT NULL DEFAULT '';
