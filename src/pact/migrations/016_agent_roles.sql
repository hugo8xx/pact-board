-- Hiring agents from roles. A role is a job description people keep in the Admin UI: what an
-- agent in it can do, the permissions and budget its mandate gets, how long it lasts, and (for a
-- Runner) the settings its machine runs with. Hiring one names the agent, registers it and issues
-- its mandate in one step; an agent that connects with a token gets a one-time setup code instead of
-- the token itself, which `pact-connect` trades for the token on the machine that will use it.
CREATE TABLE agent_roles (
  id            text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,30}$'),
  name          text NOT NULL,
  description   text NOT NULL DEFAULT '',
  client        text NOT NULL CHECK (client IN ('chat', 'cowork', 'design', 'code', 'gemini', 'runner')),
  actions       text[] NOT NULL,
  -- Project-relative actions such as task.work; a hire turns each into <action>@project:<p>.
  limits        jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(limits) = 'object'),
  delegations   integer NOT NULL DEFAULT 1 CHECK (delegations BETWEEN 0 AND 5),
  mandate_days  real NOT NULL DEFAULT 30 CHECK (mandate_days > 0 AND mandate_days <= 365),
  token_days    real NOT NULL DEFAULT 90 CHECK (token_days > 0 AND token_days <= 365),
  settings      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
  -- For a Runner: PACT_RUNNER_* settings written to its env file; {project} becomes the project id.
  instructions  text NOT NULL DEFAULT '',
  -- For a Runner: appended to its role prompt (PACT_RUNNER_ROLE_FILE).
  position      integer NOT NULL DEFAULT 100,
  archived_at   timestamptz,
  updated_at    timestamptz NOT NULL DEFAULT now(),
  updated_by    text
);

ALTER TABLE agents ADD COLUMN role_id text REFERENCES agent_roles(id);
ALTER TABLE agents ADD COLUMN replaced_by text REFERENCES agents(id);

CREATE TABLE setup_codes (
  code_hash   text PRIMARY KEY,
  agent_id    text NOT NULL REFERENCES agents(id),
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

INSERT INTO agent_roles (id, name, description, client, actions, limits, delegations, mandate_days, token_days, settings, position) VALUES
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

-- Agents registered before roles existed take the role their name and client point to (e.g. a
-- runner agent called runner-<project>), so they can be renewed from it.
UPDATE agents a SET role_id = r.id
FROM agent_roles r
WHERE a.role_id IS NULL AND r.id = split_part(a.id, '-', 1) AND r.client = a.client;
