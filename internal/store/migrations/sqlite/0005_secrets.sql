-- 0005_secrets: optional encrypted secret vault. secret_enc holds the
-- AES-256-GCM ciphertext (base64); secret_hint is a low-sensitivity masked
-- last-4 for display. Both blank when no secret is stored.
ALTER TABLE certs ADD COLUMN secret_enc TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN secret_hint TEXT NOT NULL DEFAULT '';
