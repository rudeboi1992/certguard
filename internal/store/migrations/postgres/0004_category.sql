-- 0004_category: a free "type" label so entries can be certificates, API keys,
-- subscriptions, domains, services, etc. — not just certs.
ALTER TABLE certs ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';
