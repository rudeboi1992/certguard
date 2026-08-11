-- See the sqlite copy for why this exists.
ALTER TABLE certs ADD COLUMN IF NOT EXISTS chain_json TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN IF NOT EXISTS last_chain_notified_threshold INTEGER NOT NULL DEFAULT 0;
