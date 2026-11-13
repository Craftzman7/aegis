import type { ActionName, JsonObject } from "../api/types";

export interface ParamSpec {
  name: string; label: string; kind: "string" | "int" | "select"; required?: boolean;
  min?: number; max?: number; options?: string[]; placeholder?: string; hint?: string;
}
export interface ActionSpec {
  name: ActionName; label: string; tier: number; destructive: boolean; params: ParamSpec[]; describe: (p: JsonObject) => string;
}
const ttl = (max: number, label = "TTL (seconds)"): ParamSpec => ({ name: "ttl_seconds", label, kind: "int", required: true, min: 1, max, hint: `1 to ${max}` });

export const ACTIONS: ActionSpec[] = [
  { name: "collect_evidence", label: "Collect evidence", tier: 0, destructive: false,
    params: [{ name: "kind", label: "Kind", kind: "select", required: true, options: ["process_tree", "open_files", "netconns", "file_hash", "log_excerpt", "user_info", "file_sample"] }, { name: "target", label: "Target", kind: "string" }],
    describe: (p) => `collect ${String(p.kind)} evidence${p.target ? ` for ${String(p.target)}` : ""}` },
  { name: "test_rule", label: "Test rule", tier: 0, destructive: false, params: [{ name: "yaml", label: "Sigma YAML", kind: "string", required: true }], describe: () => "run a Sigma rule against the local 24h buffer" },
  { name: "yara_scan", label: "YARA scan", tier: 0, destructive: false, params: [{ name: "path", label: "Path", kind: "string", required: true, placeholder: "/tmp" }, { name: "rules", label: "Rules (optional)", kind: "string" }], describe: (p) => `YARA scan ${String(p.path)}` },
  { name: "raise_log_level", label: "Raise log level", tier: 0, destructive: false, params: [ttl(86400)], describe: (p) => `raise log verbosity for ${String(p.ttl_seconds)}s` },
  { name: "kill_process", label: "Kill process", tier: 1, destructive: true,
    params: [{ name: "pid", label: "PID", kind: "int", required: true, min: 2, max: 4194304 }, { name: "start_time", label: "Start time (optional)", kind: "string", hint: "guards against PID reuse" }],
    describe: (p) => `terminate process PID ${String(p.pid)} (SIGKILL)` },
  { name: "block_ip", label: "Block IP", tier: 1, destructive: true,
    params: [{ name: "ip", label: "IP address", kind: "string", required: true, placeholder: "203.0.113.7" }, ttl(604800)],
    describe: (p) => `drop all traffic to/from ${String(p.ip)} for ${String(p.ttl_seconds)}s` },
  { name: "disable_user", label: "Disable user", tier: 1, destructive: true,
    params: [{ name: "username", label: "Username", kind: "string", required: true, hint: "never root/uid 0" }],
    describe: (p) => `lock account "${String(p.username)}"` },
  { name: "quarantine_file", label: "Quarantine file", tier: 1, destructive: true,
    params: [{ name: "path", label: "Absolute path", kind: "string", required: true, placeholder: "/tmp/x" }],
    describe: (p) => `move ${String(p.path)} into quarantine` },
  { name: "isolate_host", label: "Isolate host", tier: 1, destructive: true, params: [ttl(86400)],
    describe: (p) => `cut ALL network access except the Aegis server for ${String(p.ttl_seconds)}s` },
  { name: "rollback", label: "Rollback", tier: 0, destructive: false, params: [{ name: "rollback_token", label: "Rollback token", kind: "string", required: true }], describe: () => "undo a previous action" },
  { name: "adjust_threshold", label: "Adjust threshold", tier: 0, destructive: false, params: [{ name: "key", label: "Key", kind: "string", required: true }, { name: "value", label: "Value", kind: "int", required: true, min: 0, hint: "server enforces 3x / 1/3 of current" }], describe: (p) => `set threshold ${String(p.key)}=${String(p.value)}` },
  { name: "add_watch", label: "Add watch", tier: 0, destructive: false, params: [{ name: "kind", label: "Kind", kind: "select", required: true, options: ["path", "process", "port"] }, { name: "target", label: "Target", kind: "string", required: true }], describe: (p) => `watch ${String(p.kind)} ${String(p.target)}` },
  { name: "suppress", label: "Suppress", tier: 1, destructive: false, params: [{ name: "fingerprint", label: "Fingerprint", kind: "string", required: true }, ttl(604800), { name: "reason", label: "Reason", kind: "string", required: true }], describe: (p) => `suppress fingerprint ${String(p.fingerprint)}` },
  { name: "promote_rule", label: "Promote rule", tier: 1, destructive: false, params: [{ name: "rule_id", label: "Rule id", kind: "string", required: true }], describe: (p) => `promote rule ${String(p.rule_id)} to active` },
  { name: "disable_rule", label: "Disable rule", tier: 1, destructive: false, params: [{ name: "rule_id", label: "Rule id", kind: "string", required: true }], describe: (p) => `disable rule ${String(p.rule_id)}` },
];
export const actionSpec = (n: string): ActionSpec | undefined => ACTIONS.find((a) => a.name === n);
/** Actions offered in the manual-response form (host-affecting; excludes rule-management and meta). */
export const MANUAL_ACTIONS = ACTIONS.filter((a) => !["rollback", "test_rule", "promote_rule", "disable_rule", "adjust_threshold", "suppress"].includes(a.name));
/** Actions whose approval accepts an operator-chosen TTL. */
export const TTL_ACTIONS: ActionName[] = ["block_ip", "isolate_host"];

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

export type FormValues = Record<string, string>;
/** Validates raw form strings against the spec bounds; returns coerced params or per-field errors. */
export function validateParams(spec: ActionSpec, values: FormValues): { params: JsonObject; errors: Record<string, string> } {
  const params: JsonObject = {};
  const errors: Record<string, string> = {};
  for (const p of spec.params) {
    const raw = (values[p.name] ?? "").trim();
    if (!raw) {
      if (p.required) errors[p.name] = "Required";
      continue;
    }
    if (p.kind === "int") {
      const n = Number(raw);
      if (!Number.isInteger(n)) errors[p.name] = "Must be an integer";
      else if (p.min !== undefined && n < p.min) errors[p.name] = `Must be at least ${p.min}`;
      else if (p.max !== undefined && n > p.max) errors[p.name] = `Must be at most ${p.max}`;
      else params[p.name] = n;
    } else if (p.kind === "select") {
      if (p.options && !p.options.includes(raw)) errors[p.name] = "Invalid choice";
      else params[p.name] = raw;
    } else {
      params[p.name] = raw;
    }
  }
  if (typeof params.ip === "string" && !(IPV4.test(params.ip) || (params.ip.includes(":") && IPV6.test(params.ip)))) errors.ip = "Not a valid IP address";
  if (typeof params.username === "string") {
    if (params.username === "root") errors.username = "root can never be disabled";
    else if (!/^[a-z_][a-z0-9_-]{0,31}$/i.test(params.username)) errors.username = "Invalid username";
  }
  if (typeof params.path === "string" && spec.name === "quarantine_file" && !params.path.startsWith("/")) errors.path = "Must be an absolute path";
  if (spec.name === "kill_process" && params.pid === 1) errors.pid = "PID 1 is protected";
  return { params, errors };
}

/** Human description of what an action will do, for confirmation dialogs. */
export function describeAction(action: string, params: JsonObject, hostname: string): string {
  const s = actionSpec(action);
  return `${s ? s.describe(params) : action} on host ${hostname}`;
}
