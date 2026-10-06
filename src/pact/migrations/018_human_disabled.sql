-- People are never deleted: entries, mandates and projects name them. A disabled person can no
-- longer sign in or act in the Admin UI; what they issued stays as it was.
ALTER TABLE humans ADD COLUMN disabled_at timestamptz;
