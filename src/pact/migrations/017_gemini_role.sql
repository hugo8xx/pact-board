-- A role for Gemini CLI, which connects like Claude Code: an agent token written into the CLI's
-- MCP settings by pact-connect. A board whose owner already made a role called gemini keeps theirs.
INSERT INTO agent_roles (id, name, description, client, actions, limits, delegations, mandate_days, token_days, settings, position) VALUES
('gemini', 'Gemini CLI', 'Works next to the CEO in Gemini CLI, in any repository on the machine. Works only while a session is open.',
 'gemini', '{task.read,task.post,task.work,context.write}', '{}', 3, 30, 90, '{}', 25)
ON CONFLICT (id) DO NOTHING;

UPDATE agents a SET role_id = 'gemini'
FROM agent_roles r
WHERE a.role_id IS NULL AND a.client = 'gemini' AND r.id = 'gemini' AND r.client = 'gemini';
