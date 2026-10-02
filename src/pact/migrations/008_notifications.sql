-- Things a person should hear about without opening the Admin UI: a task waiting for approval, a
-- task handed back to people, a top-level task closed. Rows are written in the same transaction as
-- the event, and a separate sender delivers them, so a delivery failure never fails board work.
CREATE TABLE notifications (
  id               bigserial PRIMARY KEY,
  kind             text NOT NULL CHECK (kind IN ('approval_needed', 'deferred', 'question', 'task_closed')),
  project_id       text NOT NULL REFERENCES projects(id),
  task_id          uuid REFERENCES tasks(id),
  agent_id         text,
  title            text NOT NULL,
  detail           text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  attempts         integer NOT NULL DEFAULT 0,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  sent_at          timestamptz,
  last_error       text
);

CREATE INDEX notifications_pending ON notifications (next_attempt_at) WHERE sent_at IS NULL;
