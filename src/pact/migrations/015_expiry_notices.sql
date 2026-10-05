-- An agent stops when its root mandate or its last token expires, and a stopped runner says nothing.
-- People hear about it before (expiring) and when it happens (expired), once per mandate or token.
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
  CHECK (kind IN ('approval_needed', 'deferred', 'question', 'task_closed', 'awaiting_session', 'brief',
                  'expiring', 'expired'));

CREATE TABLE expiry_notices (
  subject   text NOT NULL,  -- mandate:<id> or token:<agent>:<expires_at>
  stage     text NOT NULL CHECK (stage IN ('expiring', 'expired')),
  queued_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (subject, stage)
);
