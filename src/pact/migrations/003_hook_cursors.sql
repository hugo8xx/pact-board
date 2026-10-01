-- Where each Claude Code session's Stop hook last looked, so it reports only tasks that are new
-- to that session. Hooks are plain shell commands, so the board keeps the `since` cursor for them.
CREATE TABLE hook_cursors (
  agent_id    text NOT NULL REFERENCES agents(id),
  session_id  text NOT NULL,
  since       bigint NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, session_id)
);
