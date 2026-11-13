-- Agentic investigation loop (docs/PROTOCOL.md §8)
CREATE TABLE agent_turns (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  run_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  role TEXT NOT NULL,                    -- user|assistant|tool
  tool_name TEXT,
  tool_call_id TEXT,
  content_json TEXT NOT NULL,
  ts TEXT NOT NULL,
  UNIQUE (run_id, seq)
);
CREATE INDEX idx_agent_turns_incident ON agent_turns(incident_id, ts);

ALTER TABLE actions ADD COLUMN critic_json TEXT;
