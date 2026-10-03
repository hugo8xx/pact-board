-- Outside signing keys whose credentials the board imports, each standing for a registered human.
-- An organization that issues its own credentials (e.g. Tenuo warrants) registers its Ed25519 key
-- here; a credential rooted at it becomes a root mandate issued by `human`. Revoking a row makes
-- every mandate imported under that key fail its chain check from then on.
CREATE TABLE trusted_roots (
  principal  bytea PRIMARY KEY CHECK (length(principal) = 32),
  human      text NOT NULL REFERENCES humans(id),
  label      text,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX trusted_roots_human ON trusted_roots (human);
