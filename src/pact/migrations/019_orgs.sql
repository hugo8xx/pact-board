-- Organizations: one deployment, many companies whose data never mixes. Expand step: every
-- row that exists today joins the organization 'default', and the new org_id columns default to it
-- so a service still running the previous release keeps working until it is replaced. A later
-- migration drops those defaults once every insert names its organization.
--
-- Ids of humans, projects and agents stay unique across the whole deployment (agent ids are part
-- of the MCP URL, tokens and scopes). A role id ("chat", "runner") repeats in every organization.

CREATE TABLE orgs (
  id                 text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  halted             boolean NOT NULL DEFAULT false,
  -- The hash chain for entries that belong to no project. It is part of every entry's hash, so the
  -- organization that already has entries keeps the chain they were written to.
  system_chain       text NOT NULL UNIQUE,
  slack_webhook_url  text,
  terms_version      text,
  terms_accepted_at  timestamptz,
  created_by         text,
  created_at         timestamptz NOT NULL DEFAULT now()
);
INSERT INTO orgs (id, name, system_chain) VALUES ('default', 'Default organization', '_system');

-- Roots carry the organization; everything else reaches it through a project, an agent or a mandate.
ALTER TABLE humans ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE projects ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE agents ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE trusted_roots ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE notifications ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
-- Not part of an entry's hash: it only lets an organization find its own log.
ALTER TABLE entries ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);

CREATE INDEX humans_org ON humans (org_id);
CREATE INDEX projects_org ON projects (org_id);
CREATE INDEX agents_org ON agents (org_id);
CREATE INDEX trusted_roots_org ON trusted_roots (org_id);
CREATE INDEX notifications_org ON notifications (org_id);
CREATE INDEX entries_org ON entries (org_id, id);

-- An agent may only belong to projects of its own organization; the database enforces it.
ALTER TABLE agents ADD CONSTRAINT agents_id_org UNIQUE (id, org_id);
ALTER TABLE projects ADD CONSTRAINT projects_id_org UNIQUE (id, org_id);
ALTER TABLE agent_projects ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE agent_projects ADD CONSTRAINT agent_projects_agent_org FOREIGN KEY (agent_id, org_id) REFERENCES agents (id, org_id);
ALTER TABLE agent_projects ADD CONSTRAINT agent_projects_project_org FOREIGN KEY (project_id, org_id) REFERENCES projects (id, org_id);

-- Roles belong to an organization; the same role id exists in each.
ALTER TABLE agents DROP CONSTRAINT agents_role_id_fkey;
ALTER TABLE agent_roles ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE agent_roles DROP CONSTRAINT agent_roles_pkey;
ALTER TABLE agent_roles ADD PRIMARY KEY (org_id, id);
ALTER TABLE agents ADD CONSTRAINT agents_role_org FOREIGN KEY (org_id, role_id) REFERENCES agent_roles (org_id, id);

-- Which task actions wait for a person's approval: each organization keeps its own list.
ALTER TABLE approval_actions ADD COLUMN org_id text NOT NULL DEFAULT 'default' REFERENCES orgs(id);
ALTER TABLE approval_actions DROP CONSTRAINT approval_actions_pkey;
ALTER TABLE approval_actions ADD PRIMARY KEY (org_id, action);

-- The roles a new organization starts with: the ones this board first shipped, kept as they were
-- (an organization's own roles may have been edited since).
CREATE TABLE role_templates (
  id            text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,30}$'),
  name          text NOT NULL,
  description   text NOT NULL DEFAULT '',
  client        text NOT NULL CHECK (client IN ('chat', 'cowork', 'design', 'code', 'gemini', 'runner')),
  actions       text[] NOT NULL,
  limits        jsonb NOT NULL DEFAULT '{}'::jsonb,
  delegations   integer NOT NULL DEFAULT 1,
  mandate_days  real NOT NULL DEFAULT 30,
  token_days    real NOT NULL DEFAULT 90,
  settings      jsonb NOT NULL DEFAULT '{}'::jsonb,
  instructions  text NOT NULL DEFAULT '',
  position      integer NOT NULL DEFAULT 100
);
INSERT INTO role_templates (id, name, description, client, actions, limits, delegations, mandate_days, token_days, settings, position) VALUES
('chat', 'Chat', 'Where the CEO gives and checks work, in claude.ai. Works only while a person has it open; posts and watches tasks, never claims them.',
 'chat', '{task.read,task.post,task.work,context.write}', '{}', 3, 30, 90, '{}', 10),
('code', 'Claude Code', 'Works next to the CEO in Claude Code, in any repository on the machine. Works only while a session is open.',
 'code', '{task.read,task.post,task.work,context.write}', '{}', 3, 30, 90, '{}', 20),
('runner', 'Runner', 'Works on its own on a machine: takes tasks delegated to it, edits code in its own clone, runs the checks and opens pull requests. Never merges.',
 'runner', '{task.read,task.post,task.work}', '{"runs": 50, "turns": 2000}', 2, 7, 90,
 '{"PACT_RUNNER_MAX_TURNS": "40", "PACT_RUNNER_RUN_TIMEOUT_MINUTES": "30", "PACT_RUNNER_MAX_RUNS_PER_DAY": "20", "PACT_RUNNER_WORKERS": "worker-{project}", "PACT_RUNNER_MAX_WAIT_HOURS": "24"}', 30),
('worker', 'Worker', 'Helps a Runner: takes the subtasks a Runner splits off. Do not hand it work directly.',
 'runner', '{task.read,task.post,task.work}', '{"runs": 50, "turns": 1000}', 1, 7, 90,
 '{"PACT_RUNNER_MAX_TURNS": "40", "PACT_RUNNER_RUN_TIMEOUT_MINUTES": "30", "PACT_RUNNER_MAX_RUNS_PER_DAY": "20"}', 40),
('secretary', 'Secretary', 'Chief of staff: sends the CEO a daily brief, turns the CEO''s orders into well-defined tasks for the other agents, follows them up and checks the results. Edits no files.',
 'runner', '{task.read,task.post,report.brief}', '{"runs": 40, "turns": 1200}', 0, 7, 90,
 '{"PACT_RUNNER_ALLOWED_TOOLS": "mcp__pact__pact_whoami,mcp__pact__pact_list,mcp__pact__pact_note,mcp__pact__pact_post", "PACT_RUNNER_MAX_TURNS": "40", "PACT_RUNNER_RUN_TIMEOUT_MINUTES": "15", "PACT_RUNNER_MAX_RUNS_PER_DAY": "20", "PACT_RUNNER_WORKERS": "runner-{project},code-{project}", "PACT_RUNNER_MAX_WAIT_HOURS": "48", "PACT_RUNNER_SCHEDULE": "[{\"at\": \"07:30\", \"title\": \"Daily brief\", \"action\": \"report.brief\", \"body\": \"Brief for {date}. Read what changed with pact_list(project_id=\\\"{project}\\\", filter=\\\"all\\\", since={since}).\"}]"}', 50),
('design', 'Claude Design', 'Design work in Claude Design. Works only while a person has it open.',
 'design', '{task.read,task.post,task.work}', '{}', 1, 30, 90, '{}', 60),
('cowork', 'Cowork', 'Document and desk work in Claude Cowork. Works only while a person has it open; posts and watches tasks.',
 'cowork', '{task.read,task.post,task.work}', '{}', 2, 30, 90, '{}', 70);

INSERT INTO role_templates (id, name, description, client, actions, limits, delegations, mandate_days, token_days, settings, position) VALUES
('gemini', 'Gemini CLI', 'Works next to the CEO in Gemini CLI, in any repository on the machine. Works only while a session is open.',
 'gemini', '{task.read,task.post,task.work,context.write}', '{}', 3, 30, 90, '{}', 25);
