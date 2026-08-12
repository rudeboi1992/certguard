-- See the sqlite copy for why this exists.
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS prf_supported INTEGER NOT NULL DEFAULT -1;
