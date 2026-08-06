-- Persist the result of a coverage check so the dashboard can act on it.
--
-- Coverage answers "which certificate actually serves each name this one
-- covers", which is computed by connecting out. It was previously calculated on
-- demand and thrown away, so a genuinely broken name — a SAN that no longer
-- resolves, and will therefore fail the next HTTP-01 renewal for the WHOLE
-- certificate — was invisible unless somebody happened to press the button.
ALTER TABLE certs ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN coverage_at TEXT NOT NULL DEFAULT '';
