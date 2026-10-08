-- Messages on a task: an agent that picked up a task can ask the agent that posted it (or another
-- agent of the project, or the people) instead of handing every question to a person. A message
-- carries no authority: it cannot approve, grant scope or change a task; it is information.
CREATE TABLE task_messages (
  id          bigserial PRIMARY KEY,
  org_id      text NOT NULL REFERENCES orgs(id),
  task_id     uuid NOT NULL REFERENCES tasks(id),
  from_agent  text REFERENCES agents(id),
  from_human  text REFERENCES humans(id),
  -- NULL: to the people of the organization.
  to_agent    text REFERENCES agents(id),
  body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 8000),
  created_at  timestamptz NOT NULL DEFAULT now(),
  read_at     timestamptz,
  CHECK ((from_agent IS NULL) <> (from_human IS NULL))
);
CREATE INDEX task_messages_task ON task_messages (task_id, id);
CREATE INDEX task_messages_inbox ON task_messages (to_agent, id) WHERE read_at IS NULL;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('approval_needed', 'deferred', 'question', 'task_closed', 'awaiting_session', 'brief',
                  'expiring', 'expired', 'message'));
