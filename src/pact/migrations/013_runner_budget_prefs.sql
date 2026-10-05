-- Runner groundwork. Each agent carries its own preferences: how it likes to work, set by people
-- and handed to the agent by pact_whoami. And a task delegated to an agent that only works while a
-- person has it open (chat, cowork, design) tells people, since nothing wakes such an agent up.
ALTER TABLE agents ADD COLUMN preferences jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(preferences) = 'object');

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('approval_needed', 'deferred', 'question', 'task_closed', 'awaiting_session'));
