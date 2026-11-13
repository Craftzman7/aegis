/**
 * THE authoritative guardrail. Every AI-originated (or manual) action request passes through `gate()`.
 * The LLM can only *request*; nothing here trusts its params. The agent re-validates independently.
 */
import { z } from "zod";
import { lintSigma } from "../sigma/lint";
import { SEV_RANK, type ActionName, type AutonomyMode, type Severity } from "../types";

export const LIMITS = {
  tier0PerHostPerHour: 20,
  tier1PerHostPerHour: 5,
  maxSuppressionTtl: 604800,
  maxIsolateTtl: 86400,
  maxBlockTtl: 604800,
  maxLogLevelTtl: 86400,
  thresholdFactor: 3,
  maxRuleYaml: 20 * 1024,
};

export interface GateRequest {
  action: string;
  params: unknown;
  reason?: string;
}

export interface GateContext {
  mode: AutonomyMode;
  /** "ai": full guardrails + autonomy; "human": bounds only, tier ignored, no autonomy/rate limits. */
  source: "ai" | "human";
  hostId: string;
  /** Effective current thresholds for the host (default + overrides). */
  thresholds: Record<string, number>;
  /** Hostnames/IPs/URLs the agent must always be able to reach. */
  serverEndpoints: string[];
  /** rule_id -> level/status, for rules referenced in the batch. */
  rules: Record<string, { level: string; status: string } | undefined>;
  /** fingerprint -> info about the anomaly it came from. */
  fingerprints: Record<string, { severity: Severity; rule_id: string; rule_level?: string } | undefined>;
  /** Actions already created for this host in the last hour (by AI). */
  tier0LastHour: number;
  tier1LastHour: number;
  /** "action:stableJSON(params)" keys of open (proposed/approved/dispatched) actions for this host. */
  openKeys: Set<string>;
  protectedUsers?: string[];
}

export interface GateDecision {
  action: string;
  accepted: boolean;
  tier: 0 | 1;
  kind: "command" | "policy";
  reason: string;
  normalizedParams: Record<string, unknown>;
  /** true when accepted but a human must approve before execution (tier 1, or propose_only mode). */
  requiresApproval: boolean;
}

type Tier = 0 | 1;
type Norm = { ok: true; params: Record<string, unknown>; tier: Tier; note?: string } | { ok: false; reason: string };

const POLICY_KINDS = new Set<string>(["adjust_threshold", "add_watch", "suppress", "propose_rule", "promote_rule", "disable_rule"]);
const COMMAND_KINDS = new Set<string>(["collect_evidence", "test_rule", "yara_scan", "raise_log_level", "kill_process", "block_ip", "disable_user", "quarantine_file", "isolate_host", "rollback"]);

export function isKnownAction(a: string): boolean {
  return POLICY_KINDS.has(a) || COMMAND_KINDS.has(a);
}
export function actionKind(a: string): "command" | "policy" {
  return POLICY_KINDS.has(a) ? "policy" : "command";
}

export function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + stableStringify(o[k])).join(",") + "}";
  }
  return JSON.stringify(v) ?? "null";
}

// ---------- primitive validators ----------
const noCtl = (s: string) => !/[\u0000-\u001f\u007f]/.test(s);
const absPath = z
  .string()
  .min(2)
  .max(1024)
  .refine(noCtl, "control characters in path")
  .refine((p) => p.startsWith("/"), "path must be absolute")
  .refine((p) => !p.split("/").includes(".."), "path traversal not allowed")
  .transform((p) => p.replace(/\/{2,}/g, "/"));

const SENSITIVE_READ = [
  /^\/etc\/(shadow|gshadow|sudoers)(\.|$)/,
  /^\/etc\/ssl\/private\//,
  /^\/var\/lib\/aegis\//,
  /^\/proc\/[^/]*\/(mem|environ)$/,
  /^\/proc\/kcore$/,
  /(^|\/)\.ssh\/id_[^/]*$/,
  /(^|\/)\.(aws|gnupg|kube)\//,
  /\.(pem|key)$/,
];
const PROTECTED_MUTATE = [
  /^\/(proc|sys|dev|boot)(\/|$)/,
  /^\/(bin|sbin|lib|lib32|lib64|usr\/bin|usr\/sbin|usr\/lib|usr\/lib64)(\/|$)/,
  /^\/var\/lib\/aegis(\/|$)/,
  /^\/etc\/(passwd|shadow|group|gshadow|sudoers|ld\.so\.preload|ssh\/sshd_config)$/,
  /^\/etc\/(sudoers\.d|systemd|pam\.d)\/?$/,
  /aegis-agent$/,
];

export function parseIp(ip: string): { v: 4; b: number[] } | { v: 6; s: string } | null {
  const m4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m4) {
    const b = m4.slice(1).map(Number);
    if (b.some((x) => x > 255)) return null;
    return { v: 4, b };
  }
  if (/^[0-9a-fA-F:.]+$/.test(ip) && ip.includes(":") && ip.length <= 45) {
    // Cheap validation: at most one '::', groups ≤ 4 hex (ignore embedded IPv4 detail but handle ::ffff:a.b.c.d below).
    if ((ip.match(/::/g) ?? []).length > 1) return null;
    const groups = ip.split(":");
    if (groups.length > 8 + 1) return null;
    for (const g of groups) {
      if (g === "") continue;
      if (g.includes(".")) {
        if (!parseIp(g)) return null;
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    }
    return { v: 6, s: ip.toLowerCase() };
  }
  return null;
}

/** True for loopback, private, link-local, CGNAT, multicast, unspecified, reserved: never blockable. */
/**
 * Never blockable: loopback, link-local, multicast, unspecified, reserved/doc ranges.
 * RFC1918 / CGNAT / ULA ARE blockable (internal attackers and lateral movement are real);
 * block_ip is tier 1, so a human always approves those.
 */
export function isUnblockableIp(ip: string): boolean {
  const p = parseIp(ip);
  if (!p) return true;
  if (p.v === 4) {
    const [a, b] = p.b as [number, number, number, number];
    return a === 0 || a === 127 || (a === 169 && b === 254) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  const s = p.s;
  if (s === "::" || s === "::1") return true;
  const mapped = /^(?:0*:)*:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) return isUnblockableIp(mapped[1]!);
  const first = s.split(":")[0] ?? "";
  const hx = first === "" ? 0 : parseInt(first, 16);
  return (hx & 0xffc0) === 0xfe80 || (hx & 0xff00) === 0xff00 || s.startsWith("2001:db8");
}

export function isNonPublicIp(ip: string): boolean {
  const p = parseIp(ip);
  if (!p) return true;
  if (p.v === 4) {
    const [a, b] = p.b as [number, number, number, number];
    return (
      a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224
    );
  }
  const s = p.s;
  if (s === "::" || s === "::1") return true;
  const mapped = /^(?:0*:)*:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s) ?? /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) return isNonPublicIp(mapped[1]!);
  const first = s.split(":")[0] ?? "";
  const hx = first === "" ? 0 : parseInt(first, 16);
  return (hx & 0xfe00) === 0xfc00 || (hx & 0xffc0) === 0xfe80 || (hx & 0xff00) === 0xff00 || s.startsWith("2001:db8");
}

function endpointHosts(endpoints: string[]): string[] {
  const out: string[] = [];
  for (const e of endpoints) {
    try {
      out.push(new URL(e.includes("://") ? e : `https://${e}`).hostname.replace(/^\[|\]$/g, "").toLowerCase());
    } catch {
      out.push(e.toLowerCase());
    }
  }
  return out;
}

const ttl = (max: number, dflt?: number) => {
  const base = z.number().int().min(60).max(max);
  return dflt === undefined ? base : base.default(dflt);
};

const reasonStr = z.string().trim().min(1).max(500);

// ---------- per-action normalizers ----------
function normalize(action: string, raw: unknown, ctx: GateContext): Norm {
  const p = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null;
  if (!p) return { ok: false, reason: "params must be an object" };
  const fail = (e: z.ZodError): Norm => ({ ok: false, reason: "invalid params: " + e.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ") });

  switch (action as ActionName) {
    case "adjust_threshold": {
      const r = z.object({ key: z.string().regex(/^[A-Za-z0-9_:.\-]{1,120}$/), value: z.number().finite().positive() }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const cur = ctx.thresholds[r.data.key];
      if (cur === undefined || !Number.isFinite(cur) || cur <= 0) return { ok: false, reason: `unknown threshold key '${r.data.key}'` };
      const ratio = r.data.value / cur;
      if (ratio > LIMITS.thresholdFactor + 1e-9 || ratio < 1 / LIMITS.thresholdFactor - 1e-9)
        return { ok: false, reason: `threshold change ${cur} -> ${r.data.value} exceeds ${LIMITS.thresholdFactor}x bound` };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "add_watch": {
      const r = z.object({ kind: z.enum(["path", "process", "port"]), target: z.string().min(1).max(256).refine(noCtl, "control chars") }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const { kind, target } = r.data;
      if (kind === "path" && (!target.startsWith("/") || target.split("/").includes(".."))) return { ok: false, reason: "path watch must be absolute without .." };
      if (kind === "port" && !(/^\d{1,5}$/.test(target) && Number(target) >= 1 && Number(target) <= 65535)) return { ok: false, reason: "port watch must be 1-65535" };
      if (kind === "process" && !/^[A-Za-z0-9_.+\-]{1,64}$/.test(target)) return { ok: false, reason: "process watch must be a plain process name" };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "suppress": {
      const r = z
        .object({ fingerprint: z.string().regex(/^[0-9a-fA-F]{16,128}$/), ttl_seconds: ttl(LIMITS.maxSuppressionTtl), reason: reasonStr })
        .strict()
        .safeParse(p);
      if (!r.success) return fail(r.error);
      const fp = ctx.fingerprints[r.data.fingerprint];
      if (!fp) return { ok: false, reason: "fingerprint not seen in any anomaly; cannot suppress" };
      if (SEV_RANK[fp.severity] >= SEV_RANK.high) return { ok: false, reason: `suppression not allowed for ${fp.severity} severity detections` };
      const lvl = fp.rule_level;
      if (lvl === "high" || lvl === "critical") return { ok: false, reason: `suppression not allowed for ${lvl} rules` };
      if (fp.rule_id.startsWith("ioc:")) return { ok: false, reason: "IOC detections cannot be suppressed" };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "propose_rule": {
      const r = z.object({ title: z.string().trim().min(1).max(200), yaml: z.string().min(10).max(LIMITS.maxRuleYaml) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const lint = lintSigma(r.data.yaml);
      if (!lint.ok) return { ok: false, reason: "rule lint failed: " + lint.errors.slice(0, 3).join("; ") };
      return { ok: true, params: r.data, tier: 0, note: "added in shadow mode" };
    }
    case "promote_rule": {
      const r = z.object({ rule_id: z.string().min(1).max(128) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const rule = ctx.rules[r.data.rule_id];
      if (!rule) return { ok: false, reason: "unknown rule" };
      if (rule.status !== "shadow") return { ok: false, reason: `rule is ${rule.status}, only shadow rules can be promoted` };
      return { ok: true, params: r.data, tier: 1 };
    }
    case "disable_rule": {
      const r = z.object({ rule_id: z.string().min(1).max(128) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const rule = ctx.rules[r.data.rule_id];
      if (!rule) return { ok: false, reason: "unknown rule" };
      if (rule.status === "disabled") return { ok: false, reason: "rule already disabled" };
      return { ok: true, params: r.data, tier: rule.level === "high" || rule.level === "critical" ? 1 : 0 };
    }
    case "collect_evidence": {
      const r = z
        .object({
          kind: z.enum(["process_tree", "open_files", "netconns", "file_hash", "log_excerpt", "user_info", "file_sample"]),
          target: z.string().min(1).max(512).refine(noCtl, "control chars").optional(),
        })
        .strict()
        .safeParse(p);
      if (!r.success) return fail(r.error);
      const { kind, target } = r.data;
      if ((kind === "file_hash" || kind === "file_sample") && !target) return { ok: false, reason: `${kind} requires a target path` };
      if (target && (kind === "file_hash" || kind === "file_sample")) {
        const ap = absPath.safeParse(target);
        if (!ap.success) return { ok: false, reason: "target: " + ap.error.issues[0]?.message };
        if (SENSITIVE_READ.some((re) => re.test(ap.data))) return { ok: false, reason: "target is a sensitive file (credentials/keys) and may not be collected" };
        r.data.target = ap.data;
      }
      if (kind === "user_info" && target && !/^[a-z_][a-z0-9_-]{0,31}\$?$/.test(target)) return { ok: false, reason: "invalid username" };
      if (kind === "process_tree" && target && !/^\d{1,9}$/.test(target)) return { ok: false, reason: "process_tree target must be a pid" };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "test_rule": {
      const r = z.object({ yaml: z.string().min(10).max(LIMITS.maxRuleYaml) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const lint = lintSigma(r.data.yaml);
      if (!lint.ok) return { ok: false, reason: "rule lint failed: " + lint.errors.slice(0, 3).join("; ") };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "yara_scan": {
      const r = z.object({ path: absPath, rules: z.string().max(LIMITS.maxRuleYaml).optional() }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      if (SENSITIVE_READ.some((re) => re.test(r.data.path))) return { ok: false, reason: "path is sensitive" };
      return { ok: true, params: r.data, tier: 0 };
    }
    case "raise_log_level": {
      const r = z.object({ ttl_seconds: ttl(LIMITS.maxLogLevelTtl, 3600) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      return { ok: true, params: r.data, tier: 0 };
    }
    case "kill_process": {
      const r = z.object({ pid: z.number().int().min(2).max(4194304), start_time: z.union([z.number().int().nonnegative(), z.iso.datetime()]).optional() }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      return { ok: true, params: r.data, tier: 1 };
    }
    case "block_ip": {
      const r = z.object({ ip: z.string().min(2).max(45), ttl_seconds: ttl(LIMITS.maxBlockTtl, 3600) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const ip = r.data.ip.trim();
      if (!parseIp(ip)) return { ok: false, reason: "not a valid IP address" };
      if (isUnblockableIp(ip)) return { ok: false, reason: "refusing to block loopback/link-local/multicast/reserved address" };
      if (endpointHosts(ctx.serverEndpoints).includes(ip.toLowerCase())) return { ok: false, reason: "refusing to block an Aegis server endpoint" };
      return { ok: true, params: { ip, ttl_seconds: r.data.ttl_seconds }, tier: 1 };
    }
    case "disable_user": {
      const r = z.object({ username: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/, "invalid username") }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      const protectedU = new Set(["root", "aegis", "aegis-agent", ...(ctx.protectedUsers ?? [])]);
      if (protectedU.has(r.data.username)) return { ok: false, reason: `refusing to disable protected user '${r.data.username}'` };
      return { ok: true, params: r.data, tier: 1 };
    }
    case "quarantine_file": {
      const r = z.object({ path: absPath }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      if (PROTECTED_MUTATE.some((re) => re.test(r.data.path))) return { ok: false, reason: "path is a protected system location" };
      return { ok: true, params: r.data, tier: 1 };
    }
    case "isolate_host": {
      const r = z.object({ ttl_seconds: ttl(LIMITS.maxIsolateTtl, 3600) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      if (ctx.serverEndpoints.length === 0) return { ok: false, reason: "no server_endpoints known; isolating would sever the agent" };
      return { ok: true, params: r.data, tier: 1 };
    }
    case "rollback": {
      if (ctx.source === "ai") return { ok: false, reason: "rollback is not available to the AI" };
      const r = z.object({ rollback_token: z.string().min(8).max(256) }).strict().safeParse(p);
      if (!r.success) return fail(r.error);
      return { ok: true, params: r.data, tier: 0 };
    }
    default:
      return { ok: false, reason: `unknown action '${action}'` };
  }
}

const rejected = (req: GateRequest, reason: string, tier: Tier = 1): GateDecision => ({
  action: String(req.action),
  accepted: false,
  tier,
  kind: actionKind(String(req.action)),
  reason,
  normalizedParams: {},
  requiresApproval: false,
});

/**
 * Evaluate a single request. `ctx` counters are NOT mutated; use `gateBatch` for sequential accounting.
 */
export function gate(req: GateRequest, ctx: GateContext): GateDecision {
  if (typeof req?.action !== "string" || !req.action) return rejected({ action: "?", params: null }, "missing action");
  if (!isKnownAction(req.action)) return rejected(req, `action '${String(req.action).slice(0, 64)}' is not in the allowed vocabulary`);
  const kind = actionKind(req.action);

  if (ctx.source === "ai" && ctx.mode === "paused") return rejected(req, "autonomy is paused: AI actions are disabled");

  const n = normalize(req.action, req.params, ctx);
  if (!n.ok) return rejected(req, n.reason);

  const key = `${req.action}:${stableStringify(n.params)}`;
  if (ctx.openKeys.has(key)) return { ...rejected(req, "duplicate of an open action", n.tier), normalizedParams: n.params };

  if (ctx.source === "ai") {
    if (n.tier === 0 && ctx.tier0LastHour >= LIMITS.tier0PerHostPerHour)
      return { ...rejected(req, `rate limit: ${LIMITS.tier0PerHostPerHour} tier-0 actions per host per hour`, 0), normalizedParams: n.params };
    if (n.tier === 1 && ctx.tier1LastHour >= LIMITS.tier1PerHostPerHour)
      return { ...rejected(req, `rate limit: ${LIMITS.tier1PerHostPerHour} tier-1 proposals per host per hour`, 1), normalizedParams: n.params };
  }

  const requiresApproval = ctx.source === "ai" && (n.tier === 1 || ctx.mode === "propose_only");
  return {
    action: req.action,
    accepted: true,
    tier: n.tier,
    kind,
    reason: n.note ?? (requiresApproval ? (n.tier === 1 ? "tier 1: human approval required" : "propose_only mode: human approval required") : "ok"),
    normalizedParams: n.params,
    requiresApproval,
  };
}

/** Evaluate requests sequentially, counting accepted ones toward rate limits and de-duplicating within the batch. */
export function gateBatch(reqs: GateRequest[], ctx: GateContext, maxRequests = 10): GateDecision[] {
  let t0 = ctx.tier0LastHour;
  let t1 = ctx.tier1LastHour;
  const keys = new Set(ctx.openKeys);
  const out: GateDecision[] = [];
  reqs.forEach((r, i) => {
    if (i >= maxRequests) {
      out.push(rejected(r, `too many requests in one review (max ${maxRequests})`));
      return;
    }
    const d = gate(r, { ...ctx, tier0LastHour: t0, tier1LastHour: t1, openKeys: keys });
    if (d.accepted) {
      if (d.tier === 0) t0++;
      else t1++;
      keys.add(`${d.action}:${stableStringify(d.normalizedParams)}`);
    }
    out.push(d);
  });
  return out;
}

// ---------- DB lookups ----------
export async function buildGateContext(
  env: Env,
  args: { hostId: string; source: "ai" | "human"; mode: AutonomyMode; thresholds: Record<string, number>; serverEndpoints: string[]; requests: GateRequest[] },
): Promise<GateContext> {
  const ruleIds = new Set<string>();
  const fps = new Set<string>();
  for (const r of args.requests) {
    const p = r?.params as Record<string, unknown> | null;
    if (p && typeof p === "object") {
      if (typeof p.rule_id === "string") ruleIds.add(p.rule_id);
      if (typeof p.fingerprint === "string") fps.add(p.fingerprint);
    }
  }
  const rules: GateContext["rules"] = {};
  for (const id of [...ruleIds].slice(0, 20)) {
    const row = await env.DB.prepare("SELECT level, status FROM rules WHERE id=?").bind(id).first<{ level: string; status: string }>();
    if (row) rules[id] = row;
  }
  const fingerprints: GateContext["fingerprints"] = {};
  for (const fp of [...fps].slice(0, 20)) {
    const rows = await env.DB.prepare("SELECT severity, rule_id FROM anomalies WHERE fingerprint=? ORDER BY ts DESC LIMIT 20").bind(fp).all<{ severity: Severity; rule_id: string }>();
    if (!rows.results.length) continue;
    let sev: Severity = "info";
    for (const r of rows.results) if (SEV_RANK[r.severity] > SEV_RANK[sev]) sev = r.severity;
    const rid = rows.results[0]!.rule_id;
    const rl = await env.DB.prepare("SELECT level FROM rules WHERE id=?").bind(rid).first<{ level: string }>();
    fingerprints[fp] = { severity: sev, rule_id: rid, rule_level: rl?.level };
  }
  const since = new Date(Date.now() - 3600_000).toISOString();
  const counts = await env.DB.prepare(
    "SELECT tier, COUNT(*) AS n FROM actions WHERE host_id=? AND proposed_by='ai' AND created_at>=? GROUP BY tier",
  ).bind(args.hostId, since).all<{ tier: number; n: number }>();
  const t0 = counts.results.find((c) => c.tier === 0)?.n ?? 0;
  const t1 = counts.results.find((c) => c.tier === 1)?.n ?? 0;
  const open = await env.DB.prepare(
    "SELECT action, params_json FROM actions WHERE host_id=? AND state IN ('proposed','approved','dispatched')",
  ).bind(args.hostId).all<{ action: string; params_json: string }>();
  const openKeys = new Set<string>();
  for (const o of open.results) {
    try {
      openKeys.add(`${o.action}:${stableStringify(JSON.parse(o.params_json))}`);
    } catch {
      /* ignore */
    }
  }
  return {
    mode: args.mode,
    source: args.source,
    hostId: args.hostId,
    thresholds: args.thresholds,
    serverEndpoints: args.serverEndpoints,
    rules,
    fingerprints,
    tier0LastHour: t0,
    tier1LastHour: t1,
    openKeys,
  };
}
