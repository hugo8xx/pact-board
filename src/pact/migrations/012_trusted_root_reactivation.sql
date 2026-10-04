-- A revoked trusted root can be trusted again, but revoking stays final for what was imported
-- before: a mandate imported under a key counts only if it was imported after the key's latest
-- activation. Re-adding a key therefore never revives an old credential; it has to be imported anew.
ALTER TABLE trusted_roots ADD COLUMN active_since timestamptz;
UPDATE trusted_roots SET active_since = created_at;
ALTER TABLE trusted_roots ALTER COLUMN active_since SET NOT NULL, ALTER COLUMN active_since SET DEFAULT now();
