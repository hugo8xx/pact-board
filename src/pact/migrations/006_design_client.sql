-- Claude Design gets its own agent: unlike chat it claims and reports the design tasks it takes.
ALTER TABLE agents DROP CONSTRAINT agents_client_check;
ALTER TABLE agents ADD CONSTRAINT agents_client_check
  CHECK (client IN ('chat', 'cowork', 'design', 'code', 'gemini', 'runner'));
