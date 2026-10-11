-- pact_events: a long-poll that answers as soon as there is work or a message for the agent.
--
-- One cursor covers both: messages take their seq from the same sequence as tasks.change_seq, so
-- a pact_list next_since is also a pact_events since. Existing messages get a value each.
ALTER TABLE task_messages ADD COLUMN seq bigint NOT NULL DEFAULT nextval('task_change_seq');
CREATE INDEX task_messages_unread_seq ON task_messages (to_agent, seq) WHERE read_at IS NULL;

-- A waiting pact_events on any board instance hears about a change through NOTIFY, sent when the
-- writing transaction commits. The payload is the organization only; waiters re-read the database.
CREATE FUNCTION tasks_notify_events() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('pact_events', coalesce((SELECT org_id FROM projects WHERE id = NEW.project_id), ''));
  RETURN NULL;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER tasks_notify_events AFTER INSERT OR UPDATE ON tasks
  FOR EACH ROW EXECUTE FUNCTION tasks_notify_events();

CREATE FUNCTION task_messages_notify_events() RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('pact_events', NEW.org_id);
  RETURN NULL;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER task_messages_notify_events AFTER INSERT ON task_messages
  FOR EACH ROW EXECUTE FUNCTION task_messages_notify_events();

-- Holding pact_events open is the agent's heartbeat: until when its current wait runs.
ALTER TABLE agents ADD COLUMN listening_until timestamptz;
