-- Every outside id minted for a ledger link. One export of a chain mints a piece for each of its
-- links (a Tenuo warrant per link), and each export mints new ids, so revoking any link must
-- find every id ever minted for it, not only the one on mandates.external_id.
CREATE TABLE credential_links (
  mandate_id  uuid NOT NULL REFERENCES mandates(id),
  format      text NOT NULL CHECK (format IN ('tenuo', 'biscuit')),
  external_id text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (format, external_id)
);

CREATE INDEX credential_links_mandate ON credential_links (mandate_id);

-- Outside ids revoked on the board, published as a signed list for outside verifiers. Rows are
-- written in the same transaction that revokes the ledger link. `expires_at` is the ledger
-- link's expiry: once it passes, the credential is dead anyway and the id leaves the list.
CREATE TABLE credential_revocations (
  external_id text PRIMARY KEY,
  format      text NOT NULL CHECK (format IN ('tenuo', 'biscuit')),
  revoked_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz
);

-- The published list's version per format. Bumped under a row lock by every revoke that adds ids,
-- so versions follow commit order and a verifier never sees new ids under an old version.
CREATE TABLE credential_revocation_version (
  format  text PRIMARY KEY CHECK (format IN ('tenuo', 'biscuit')),
  version bigint NOT NULL DEFAULT 0
);
