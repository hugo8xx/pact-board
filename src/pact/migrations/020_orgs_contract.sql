-- Organizations, contract step: every insert now names its organization (019 kept a default of
-- 'default' only so the release before it could keep writing while it was replaced). Without the
-- default, a row that forgets its organization fails instead of quietly joining the first one.
ALTER TABLE humans ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE projects ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE agents ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE trusted_roots ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE notifications ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE entries ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE agent_projects ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE agent_roles ALTER COLUMN org_id DROP DEFAULT;
ALTER TABLE approval_actions ALTER COLUMN org_id DROP DEFAULT;
