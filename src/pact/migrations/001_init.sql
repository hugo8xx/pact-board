-- PACT Board core schema: Project, Agent, Mandate, Task, Entry (+ supporting tables).

CREATE TABLE humans (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  role        text NOT NULL CHECK (role IN ('owner', 'approver', 'viewer')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
  id          text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  name        text NOT NULL,
  production  boolean NOT NULL DEFAULT false,
  frozen      boolean NOT NULL DEFAULT false,
  created_by  text NOT NULL REFERENCES humans(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
  id               text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  owner            text NOT NULL REFERENCES humans(id),
  client           text NOT NULL CHECK (client IN ('chat', 'cowork', 'code', 'gemini', 'runner')),
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'banned')),
  root_mandate_id  uuid,
  last_seen        timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_projects (
  agent_id    text NOT NULL REFERENCES agents(id),
  project_id  text NOT NULL REFERENCES projects(id),
  PRIMARY KEY (agent_id, project_id)
);

-- Bearer tokens for agents that cannot use OAuth (hooks, Runner) and for local development.
-- Only the SHA-256 of the token is stored.
CREATE TABLE agent_tokens (
  token_hash  text PRIMARY KEY,
  agent_id    text NOT NULL REFERENCES agents(id),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mandates (
  id                uuid PRIMARY KEY,
  parent_id         uuid REFERENCES mandates(id),
  issuer_kind       text NOT NULL CHECK (issuer_kind IN ('human', 'agent')),
  issuer            text NOT NULL,
  holder            text NOT NULL REFERENCES agents(id),
  scope             text[] NOT NULL,
  limits            jsonb NOT NULL DEFAULT '{}'::jsonb,
  delegations_left  integer NOT NULL CHECK (delegations_left >= 0),
  depth             integer NOT NULL CHECK (depth >= 0),
  expires_at        timestamptz NOT NULL,
  revoked_at        timestamptz,
  signature         text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CHECK ((parent_id IS NULL) = (issuer_kind = 'human'))
);
CREATE INDEX mandates_parent_idx ON mandates(parent_id);
CREATE INDEX mandates_holder_idx ON mandates(holder);

ALTER TABLE agents ADD FOREIGN KEY (root_mandate_id) REFERENCES mandates(id);

-- Aggregate usage per mandate per limit key. Every consumption is added to every
-- mandate in the chain, so children split from one parent share its ceiling.
CREATE TABLE limit_usage (
  mandate_id  uuid NOT NULL REFERENCES mandates(id),
  limit_key   text NOT NULL,
  used        numeric NOT NULL DEFAULT 0,
  PRIMARY KEY (mandate_id, limit_key)
);

-- Task actions that must wait for a human approval before anyone can claim them.
-- A trailing ".*" matches any sub-action.
CREATE TABLE approval_actions (
  action  text PRIMARY KEY
);

CREATE SEQUENCE task_change_seq;

CREATE TABLE tasks (
  id                   uuid PRIMARY KEY,
  project_id           text NOT NULL REFERENCES projects(id),
  title                text NOT NULL,
  body                 text NOT NULL DEFAULT '',
  action               text NOT NULL DEFAULT 'task.work',
  created_by           text NOT NULL REFERENCES agents(id),
  mandate_id           uuid NOT NULL REFERENCES mandates(id),
  delegate_to          text REFERENCES agents(id),
  delegated_mandate_id uuid REFERENCES mandates(id),
  assignee             text REFERENCES agents(id),
  assignee_mandate_id  uuid REFERENCES mandates(id),
  status               text NOT NULL CHECK (status IN ('submitted', 'working', 'input_required', 'auth_required',
                                                     'completed', 'failed', 'canceled', 'rejected')),
  deferred             boolean NOT NULL DEFAULT false,
  defer_reason         text,
  needed_scope         text[],
  result               jsonb,
  approved_by          text REFERENCES humans(id),
  approved_at          timestamptz,
  claimed_at           timestamptz,
  parent_task_id       uuid REFERENCES tasks(id),
  change_seq           bigint NOT NULL DEFAULT nextval('task_change_seq'),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tasks_project_seq_idx ON tasks(project_id, change_seq);
CREATE INDEX tasks_working_idx ON tasks(status) WHERE status = 'working';

-- Heartbeat of the assignee. Kept outside `tasks` so a heartbeat does not move the
-- task's change_seq (which would resurface it in every pact_list `since` call).
CREATE TABLE task_activity (
  task_id   uuid PRIMARY KEY REFERENCES tasks(id),
  agent_id  text NOT NULL REFERENCES agents(id),
  at        timestamptz NOT NULL
);

-- Every change to a task moves it forward in the change sequence, which is what
-- pact_list's `since` cursor reads.
CREATE FUNCTION tasks_touch() RETURNS trigger AS $$
BEGIN
  NEW.change_seq := nextval('task_change_seq');
  NEW.updated_at := now();
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER tasks_touch BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION tasks_touch();

-- Deletable store for entry payloads (PDPA erasure). Entries keep only the hash.
CREATE TABLE payloads (
  id          uuid PRIMARY KEY,
  content     jsonb,
  erased_at   timestamptz
);

CREATE TABLE entries (
  id             bigserial PRIMARY KEY,
  chain_key      text NOT NULL,
  project_id     text REFERENCES projects(id),
  task_id        uuid REFERENCES tasks(id),
  agent_id       text REFERENCES agents(id),
  actor          text NOT NULL,
  mandate_chain  uuid[] NOT NULL DEFAULT '{}',
  action         text NOT NULL,
  payload_hash   text NOT NULL,
  payload_ref    uuid REFERENCES payloads(id),
  outcome        text NOT NULL,
  at             timestamptz NOT NULL,
  prev_hash      text NOT NULL,
  hash           text NOT NULL
);
CREATE INDEX entries_chain_idx ON entries(chain_key, id);
CREATE INDEX entries_task_idx ON entries(task_id);

-- One hash chain per project (plus "_system" for calls with no project), so writes in
-- different projects never queue behind each other.
CREATE TABLE entry_chain_heads (
  chain_key  text PRIMARY KEY,
  last_hash  text NOT NULL
);

CREATE FUNCTION entries_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'entries are append-only';
END $$ LANGUAGE plpgsql;
CREATE TRIGGER entries_no_update BEFORE UPDATE OR DELETE ON entries
  FOR EACH ROW EXECUTE FUNCTION entries_append_only();

CREATE TABLE system_state (
  id       boolean PRIMARY KEY DEFAULT true CHECK (id),
  halted   boolean NOT NULL DEFAULT false
);
INSERT INTO system_state DEFAULT VALUES;

INSERT INTO approval_actions (action) VALUES ('deploy.*'), ('finance.*'), ('customer.message');
