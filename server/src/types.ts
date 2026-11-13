// Shared domain types (wire contract: docs/PROTOCOL.md). Bindings come from worker-configuration.d.ts.
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
export const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export type AutonomyMode = "autonomous" | "propose_only" | "paused";

export const AGENT_ACTIONS = [
  "collect_evidence",
  "test_rule",
  "yara_scan",
  "raise_log_level",
  "kill_process",
  "block_ip",
  "disable_user",
  "quarantine_file",
  "isolate_host",
  "rollback",
] as const;
export type AgentAction = (typeof AGENT_ACTIONS)[number];

export const POLICY_ACTIONS = [
  "adjust_threshold",
  "add_watch",
  "suppress",
  "propose_rule",
  "promote_rule",
  "disable_rule",
] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];
export type ActionName = AgentAction | PolicyAction;

export interface SignedEnvelope {
  payload: string;
  sig: string;
}

export interface Command {
  id: string;
  host_id: string;
  action: AgentAction;
  params: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
}

export interface PolicyBody {
  log_level: "info" | "debug";
  thresholds: Record<string, number>;
  watches: { kind: "path" | "process" | "port"; target: string }[];
  suppressions: { fingerprint: string; expires_at: string; reason: string }[];
  rules: { id: string; status: "active" | "shadow" | "disabled"; yaml: string }[];
  iocs: { type: "ip" | "sha256" | "domain"; value: string }[];
  server_endpoints: string[];
}

/** What is stored in policies.body_json: the editable part only (rules/iocs/endpoints are composed at serve time). */
export type StoredPolicyBody = Partial<Pick<PolicyBody, "log_level" | "thresholds" | "watches" | "suppressions">>;

export interface HostRow {
  id: string;
  hostname: string;
  os: string | null;
  arch: string | null;
  kernel: string | null;
  agent_version: string | null;
  pubkey: string;
  policy_version: number;
  autonomy: AutonomyMode | null;
  status: "ok" | "degraded" | "isolated";
  stats_json: string | null;
  rule_errors_json: string | null;
  enrolled_at: string;
  last_seen: string | null;
}

export interface IncidentRow {
  id: string;
  host_id: string;
  title: string;
  status: string;
  verdict: string | null;
  severity: Severity;
  confidence: number | null;
  attack_tags_json: string;
  ai_summary: string | null;
  analyst_note: string | null;
  workflow_id: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface AnomalyRow {
  id: string;
  host_id: string;
  incident_id: string | null;
  ts: string;
  rule_id: string;
  rule_source: string;
  rule_title: string | null;
  category: string;
  severity: Severity;
  fingerprint: string;
  summary: string;
  attack_tags_json: string;
  falsepositives_json: string;
  shadow: number;
  evidence_json: string | null;
  evidence_r2_key: string | null;
  received_at: string;
}

export interface ActionRow {
  id: string;
  incident_id: string | null;
  host_id: string;
  action: string;
  params_json: string;
  tier: number;
  kind: "command" | "policy";
  state: string;
  proposed_by: string;
  rationale: string | null;
  approved_by: string | null;
  reject_reason: string | null;
  result_json: string | null;
  error: string | null;
  rollback_token: string | null;
  rollback_of: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RuleRow {
  id: string;
  pack_id: string;
  title: string;
  level: string;
  logsource: string | null;
  attack_tags_json: string;
  yaml: string;
  status: "active" | "shadow" | "disabled";
  created_by: string;
  hits_total: number;
  fp_total: number;
  tp_total: number;
  shadow_since: string | null;
  created_at: string;
  updated_at: string;
}

export type FleetEventType = "anomaly" | "incident" | "ai_review" | "action" | "host" | "audit" | "policy";
