-- Persist the certificate chain served under the leaf, and track chain alerts
-- separately from leaf alerts.
--
-- The scanner always had the whole chain in hand during the handshake and kept
-- only its length, so an intermediate expiring BEFORE the leaf was invisible:
-- certguard reported the endpoint healthy right up to the moment it broke,
-- which is the one thing it exists to prevent. This is the shape of the 2021
-- DST Root expiry, where perfectly valid leaves went dark because something
-- above them lapsed.
--
-- last_chain_notified_threshold is its own counter rather than a reuse of
-- last_notified_threshold: sharing one would let whichever fired first silence
-- the other. There is deliberately no last_chain_notified_on — the activity log
-- already timestamps the alert, and an unread column is worse than no column.
ALTER TABLE certs ADD COLUMN chain_json TEXT NOT NULL DEFAULT '';
ALTER TABLE certs ADD COLUMN last_chain_notified_threshold INTEGER NOT NULL DEFAULT 0;
