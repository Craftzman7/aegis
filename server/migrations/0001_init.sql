-- Aegis D1 schema (contract; see docs/PROTOCOL.md)
CREATE TABLE hosts (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os TEXT, arch TEXT, kernel TEXT,
  agent_version TEXT,
  pubkey TEXT NOT NULL,
  policy_version INTEGER NOT NULL DEFAULT 0,
  autonomy TEXT,                         -- NULL = inherit global
  status TEXT NOT NULL DEFAULT 'ok',     -- ok|degraded|isolated
  stats_json TEXT,
  rule_errors_json TEXT,
  enrolled_at TEXT NOT NULL,
  last_seen TEXT
);

CREATE TABLE enroll_tokens (
  token_hash TEXT PRIMARY KEY,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  host_id TEXT
);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES hosts(id),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',   -- open|investigating|awaiting_approval|contained|closed_benign|closed_tp
  verdict TEXT,                          -- benign|suspicious|malicious|true_positive|false_positive
  severity TEXT NOT NULL DEFAULT 'low',
  confidence REAL,
  attack_tags_json TEXT NOT NULL DEFAULT '[]',
  ai_summary TEXT,
  analyst_note TEXT,
  workflow_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX idx_incidents_host_status ON incidents(host_id, status);
CREATE INDEX idx_incidents_status ON incidents(status, updated_at);

CREATE TABLE anomalies (
  id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES hosts(id),
  incident_id TEXT REFERENCES incidents(id),
  ts TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_source TEXT NOT NULL,
  rule_title TEXT,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  summary TEXT NOT NULL,
  attack_tags_json TEXT NOT NULL DEFAULT '[]',
  falsepositives_json TEXT NOT NULL DEFAULT '[]',
  shadow INTEGER NOT NULL DEFAULT 0,
  evidence_json TEXT,                    -- small evidence inline
  evidence_r2_key TEXT,                  -- large evidence in R2
  received_at TEXT NOT NULL
);
CREATE INDEX idx_anomalies_host_ts ON anomalies(host_id, ts);
CREATE INDEX idx_anomalies_incident ON anomalies(incident_id);
CREATE INDEX idx_anomalies_rule ON anomalies(rule_id, ts);
CREATE INDEX idx_anomalies_fp ON anomalies(fingerprint);

CREATE TABLE ai_reviews (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  step TEXT NOT NULL,                    -- triage|reanalyze|final|ask
  round INTEGER NOT NULL DEFAULT 0,
  model TEXT NOT NULL,
  prompt_hash TEXT,
  output_json TEXT NOT NULL,             -- {verdict, severity, confidence, rationale, requests[]}
  gate_json TEXT,                        -- per-request gate decisions [{action, tier, accepted, reason}]
  ts TEXT NOT NULL
);
CREATE INDEX idx_reviews_incident ON ai_reviews(incident_id, ts);

CREATE TABLE actions (
  id TEXT PRIMARY KEY,
  incident_id TEXT REFERENCES incidents(id),
  host_id TEXT NOT NULL REFERENCES hosts(id),
  action TEXT NOT NULL,
  params_json TEXT NOT NULL,
  tier INTEGER NOT NULL,
  kind TEXT NOT NULL,                    -- command|policy
  state TEXT NOT NULL,                   -- proposed|approved|rejected|dispatched|succeeded|failed|rolled_back|expired
  proposed_by TEXT NOT NULL,             -- ai|human:<email>
  rationale TEXT,
  approved_by TEXT,
  reject_reason TEXT,
  result_json TEXT,
  error TEXT,
  rollback_token TEXT,
  rollback_of TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_actions_state ON actions(state, tier);
CREATE INDEX idx_actions_host ON actions(host_id, created_at);
CREATE INDEX idx_actions_incident ON actions(incident_id);

CREATE TABLE policies (
  host_id TEXT NOT NULL,                 -- host id or 'default'
  version INTEGER NOT NULL,
  body_json TEXT NOT NULL,
  created_by TEXT NOT NULL,              -- ai|human:<email>|system
  reason TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (host_id, version)
);

CREATE TABLE rule_packs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL,                  -- sigmahq|custom|ai
  version TEXT NOT NULL,
  r2_key TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE rules (
  id TEXT PRIMARY KEY,                   -- sigma id (uuid) or generated
  pack_id TEXT NOT NULL REFERENCES rule_packs(id),
  title TEXT NOT NULL,
  level TEXT NOT NULL,
  logsource TEXT,
  attack_tags_json TEXT NOT NULL DEFAULT '[]',
  yaml TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active|shadow|disabled
  created_by TEXT NOT NULL,
  hits_total INTEGER NOT NULL DEFAULT 0,
  fp_total INTEGER NOT NULL DEFAULT 0,
  tp_total INTEGER NOT NULL DEFAULT 0,
  shadow_since TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_rules_status ON rules(status);

CREATE TABLE iocs (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,                    -- ip|sha256|domain
  value TEXT NOT NULL,
  source TEXT NOT NULL,                  -- import:<name>|incident|ai
  incident_id TEXT,
  watch INTEGER NOT NULL DEFAULT 1,      -- pushed to agents
  first_seen TEXT NOT NULL,
  UNIQUE(type, value)
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO settings(key, value) VALUES ('autonomy', 'autonomous');

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,                   -- ai|human:<email>|agent:<host>|system
  event TEXT NOT NULL,                   -- e.g. action.proposed, action.approved, policy.updated, gate.rejected
  incident_id TEXT,
  host_id TEXT,
  action_id TEXT,
  detail_json TEXT
);
CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_incident ON audit_log(incident_id);
