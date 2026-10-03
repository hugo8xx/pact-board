-- The ledger stays the source of truth; these columns let a mandate also be a standard
-- credential. `format` says where a link came from: `pact` for one the board issued, else the
-- format it was imported from. `exported_as` names the format a board-issued link was exported
-- in. `external_id` and `credential` hold that credential; `issuer_principal` names the outside
-- key that issued an imported link.
ALTER TABLE mandates
  ADD COLUMN format text NOT NULL DEFAULT 'pact' CHECK (format IN ('pact', 'tenuo', 'biscuit')),
  ADD COLUMN exported_as text CHECK (exported_as IN ('tenuo', 'biscuit')),
  ADD COLUMN external_id text,
  ADD COLUMN credential bytea,
  ADD COLUMN issuer_principal text;

CREATE UNIQUE INDEX mandates_external_id ON mandates (coalesce(exported_as, format), external_id) WHERE external_id IS NOT NULL;
ALTER TABLE mandates ADD CONSTRAINT mandates_export_is_ours CHECK (exported_as IS NULL OR format = 'pact');

-- Ed25519 public keys of agents that call verifiers outside the board, which check every call
-- against the holder's key (proof of possession). Only code and runner agents get keys for now.
CREATE TABLE agent_keys (
  agent_id    text NOT NULL REFERENCES agents(id),
  kid         text NOT NULL,
  public_key  bytea NOT NULL CHECK (length(public_key) = 32),
  created_at  timestamptz NOT NULL DEFAULT now(),
  created_by  text NOT NULL,
  revoked_at  timestamptz,
  PRIMARY KEY (agent_id, kid)
);

CREATE UNIQUE INDEX agent_keys_public_key ON agent_keys (public_key);
