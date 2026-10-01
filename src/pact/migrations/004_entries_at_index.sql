-- The audit log filters by time (from / to).
CREATE INDEX entries_at_idx ON entries (at);
