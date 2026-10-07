-- Cowork does desk work for a person (research, reports, documents), so its agents now claim tasks
-- like Design does. Only the wording of the role changes; its actions already include task.work.
-- Organizations that edited the description keep theirs.
UPDATE role_templates
   SET description = 'Document and desk work in Claude Cowork: research, reports and documents. Works only while a person has it open; posts tasks and does its own.'
 WHERE id = 'cowork';
UPDATE agent_roles
   SET description = 'Document and desk work in Claude Cowork: research, reports and documents. Works only while a person has it open; posts tasks and does its own.'
 WHERE id = 'cowork'
   AND description = 'Document and desk work in Claude Cowork. Works only while a person has it open; posts and watches tasks.';
