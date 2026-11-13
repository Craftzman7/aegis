// Mirrors docs/PROTOCOL.md sections 4-7 and server/migrations/0001_init.sql.
// Console API rows have *_json columns parsed into the key minus the suffix.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type JsonObject = Record<string, unknown>;

export type AutonomyMode = "autonomous" | "propose_only" | "paused";
export type HostStatus = "ok" | "degraded" | "isolated";

export type IncidentStatus =
  | "open" | "investigating" | "awaiting_approval" | "contained" | "resolved" | "closed_benign" | "closed_tp";
export type Verdict = "benign" | "suspicious" | "malicious" | "true_positive" | "false_positive";

export type ActionState =
  | "proposed" | "approved" | "rejected" | "dispatched" | "succeeded" | "failed" | "rolled_back" | "expired";

export type AgentAction =
  | "collect_evidence" | "test_rule" | "yara_scan" | "raise_log_level" | "kill_process"
  | "block_ip" | "disable_user" | "quarantine_file" | "isolate_host" | "rollback";
export type ServerAction =
  | "adjust_threshold" | "add_watch" | "suppress" | "propose_rule" | "promote_rule" | "disable_rule";
export type ActionName = AgentAction | ServerAction;

export interface Host {
  id: string; hostname: string; os: string | null; arch: string | null; kernel: string | null;
  agent_version: string | null; policy_version: number;
  autonomy: AutonomyMode | null; status: HostStatus;
  stats: HostStats | null; rule_errors: RuleError[] | null;
  enrolled_at: string; last_seen: string | null;
  open_incidents?: number; // optional convenience count from list endpoint
}
export interface HostStats {
  events_per_min?: number; anomalies_per_min?: number; rules_loaded?: number; buffer_events?: number;
  uptime_s?: number; ws_connected?: boolean;
}
export interface RuleError { rule_id: string; error: string }

export interface Incident {
  id: string; host_id: string; title: string; status: IncidentStatus; verdict: Verdict | null;
  severity: Severity; confidence: number | null; attack_tags: string[];
  ai_summary: string | null; analyst_note: string | null; workflow_id: string | null;
  created_at: string; updated_at: string; closed_at: string | null;
  hostname?: string; // optional join
}

export type RuleSource = "sigma" | "native" | "baseline" | "ioc" | "yara";
export interface Anomaly {
  id: string; host_id: string; incident_id: string | null; ts: string;
  rule_id: string; rule_source: RuleSource; rule_title: string | null;
  category: string; severity: Severity; fingerprint: string; summary: string;
  attack_tags: string[]; falsepositives: string[]; shadow: number | boolean;
  evidence: JsonObject | null; evidence_r2_key: string | null; received_at: string;
}

export interface ActionRequest { action: ActionName; params: JsonObject; rationale?: string }
export interface AiOutput {
  verdict: Verdict; severity: Severity; confidence: number; rationale: string; requests: ActionRequest[];
}
export interface GateDecision { action: ActionName; tier: number; accepted: boolean; reason: string }
export interface AiReview {
  id: string; incident_id: string; step: "triage" | "reanalyze" | "final" | "ask"; round: number;
  model: string; prompt_hash: string | null; output: AiOutput; gate: GateDecision[] | null; ts: string;
}

export interface CriticNotes { decision: "submit" | "revise"; concerns: string[]; missing_checks: string[]; round: number }

export interface AgentToolCall { id: string; name: string; arguments: JsonObject }
export interface AgentTurn {
  id: string; incident_id: string; run_id: string; seq: number; ts: string;
  role: "user" | "assistant" | "tool"; tool_name: string | null; tool_call_id: string | null;
  content: { text?: string; tool_calls?: AgentToolCall[]; result?: unknown; error?: string; action_id?: string };
}

export interface ActionRow {
  id: string; incident_id: string | null; host_id: string; action: ActionName; params: JsonObject;
  tier: number; kind: "command" | "policy"; state: ActionState; proposed_by: string;
  rationale: string | null; approved_by: string | null; reject_reason: string | null;
  result: JsonObject | null; error: string | null; rollback_token: string | null; rollback_of: string | null;
  expires_at: string | null; created_at: string; updated_at: string;
  critic?: CriticNotes | null;
}
/** Approval inbox item: action row joined with its incident and host. */
export interface Approval extends ActionRow {
  incident?: Incident | null; host?: Host | null;
}

export interface AuditEntry {
  id: number; ts: string; actor: string; event: string; incident_id: string | null;
  host_id: string | null; action_id: string | null; detail: unknown;
}

export interface PolicyBody {
  log_level: "info" | "debug";
  thresholds: Record<string, number>;
  watches: { kind: "path" | "process" | "port"; target: string }[];
  suppressions: { fingerprint: string; expires_at: string; reason: string }[];
  rules: { id: string; status: RuleStatus; yaml: string }[];
  iocs: { type: "ip" | "sha256" | "domain"; value: string }[];
  server_endpoints: string[];
}
export interface PolicyRow {
  host_id: string; version: number; body: PolicyBody; created_by: string; reason: string | null; created_at: string;
}

export type RuleStatus = "active" | "shadow" | "disabled";
export interface Rule {
  id: string; pack_id: string; pack_name?: string; title: string; level: Severity; logsource: string | null;
  attack_tags: string[]; yaml: string; status: RuleStatus; created_by: string;
  hits_total: number; fp_total: number; tp_total: number; shadow_since: string | null;
  created_at: string; updated_at: string;
}

export interface Overview {
  hosts: { total: number; online: number; offline: number; isolated: number };
  incidents_by_severity: Partial<Record<Severity, number>>;
  pending_approvals: number;
  anomalies_24h_hourly: { hour: string; count: number }[];
  ai_actions_24h: number;
  autonomy: AutonomyMode;
}

export interface HostDetail {
  host: Host; anomalies: Anomaly[]; incidents: Incident[]; actions: ActionRow[]; policy: PolicyRow | null;
}
export interface IncidentDetail {
  incident: Incident; anomalies: Anomaly[]; reviews: AiReview[]; actions: ActionRow[]; audit: AuditEntry[];
  turns?: AgentTurn[];
  host?: Host | null;
}

export interface Coverage { techniques: { id: string; rules: number | string[]; hits_30d: number }[] }
export interface LintResult { ok: boolean; errors: (string | { message: string; line?: number })[] }
export interface TestResult { matches?: number; samples?: unknown[]; [k: string]: unknown }

export type LiveType = "anomaly" | "incident" | "ai_review" | "action" | "host" | "audit" | "policy" | "agent_turn";
export interface LiveMessage { type: LiveType; data: Record<string, unknown>; ts: string }
