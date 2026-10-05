-- A daily brief: when a task of action report.brief completes, its whole result goes to people as
-- one message, not just a heads-up that the task closed.
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('approval_needed', 'deferred', 'question', 'task_closed', 'awaiting_session', 'brief'));
