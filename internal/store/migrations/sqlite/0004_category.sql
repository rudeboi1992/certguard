-- 0004_category: a free "type" label so entries can be certificates, API keys,
-- subscriptions, domains, services, etc. — not just certs.
ALTER TABLE certs ADD COLUMN category TEXT NOT NULL DEFAULT '';
