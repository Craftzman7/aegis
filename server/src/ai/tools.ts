/**
 * Tool table for the investigation loop. Each entry: name, description, zod schema (shape only: bounds live in the gate),
 * JSON schema for the model (derived from the zod schema), kind and handler.
 * Every host-affecting call goes through gate() then createAction/dispatchAction. There is no other execution path.
 */
import { z } from "zod";
import { createAction, dispatchAction, getAction, getAutonomy, PROPOSAL_TTL_S } from "../lib/actions";
import { audit } from "../lib/audit";
import { getIncident } from "../lib/incidents";
import { recordReview } from "../lib/reviews";
import { deterministicUuid, errMsg, safeJson, sha256Hex, truncate } from "../lib/util";
import { buildGateContext, gateBatch, parseIp, stableStringify } from "../policy/gate";
import { effectiveThresholds, getServerEndpoints } from "../policy/service";
import type { ActionRow, AnomalyRow, CriticNotes } from "../types";
import { critique } from "./critic";
import { findSimilar } from "./memory";
import type { ToolSpec } from "./runner";
import { getTurn } from "./transcript";

export interface ToolCtx {
  env: Env;
  incidentId: string;
  hostId: string;
  runId: string;
  /** turn index and call index; make action ids deterministic so step retries never duplicate */
  n: number;
  i: number;
}
export type WaitSpec = { kind: "action"; action_id: string } | { kind: "approvals" };
export interface ToolOutcome {
  result?: unknown;
  error?: string;
  action_id?: string;
  wait?: WaitSpec;
  done?: boolean;
}
export type ToolKind = "host" | "policy" | "propose" | "approvals" | "server" | "finish";
export interface ToolDef {
  name: string;
  description: string;
  kind: ToolKind;
  schema: z.ZodType;
  json: Record<string, unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handler: (ctx: ToolCtx, args: any) => Promise<ToolOutcome>;
}

const SERVER_ROW_CAP = 50;
const TERMINAL = new Set(["succeeded", "failed", "expired", "rejected", "rolled_back"]);
export const isTerminal = (state: string) => TERMINAL.has(state);

function def<S extends z.ZodType>(name: string, kind: ToolKind, description: string, schema: S, handler: (ctx: ToolCtx, args: z.output<S>) => Promise<ToolOutcome>): ToolDef {
  const json = z.toJSONSchema(schema, { unrepresentable: "any", io: "input" }) as Record<string, unknown>;
  delete json.$schema;
  return { name, kind, description, schema, json, handler };
}

// ---------- gated execution ----------
async function execGated(ctx: ToolCtx, action: string, params: unknown, reason: string, opts: { propose: boolean }): Promise<ToolOutcome> {
  const { env } = ctx;
  const id = await deterministicUuid(`action:${ctx.runId}:${ctx.n}:${ctx.i}`);
  // Step retry after a partial run: resume from the stored row instead of re-gating (the gate would call it a duplicate).
  const prev = await getAction(env, id);
  if (prev) {
    if (prev.state === "rejected" && !prev.approved_by) return { error: `gate rejected: ${prev.reject_reason}`, action_id: id };
    if (prev.tier === 1 || prev.state === "proposed") return { result: { status: "submitted for human approval", note: "Call wait_for_approvals to learn the outcome." }, action_id: id };
    if (prev.kind === "command" && !isTerminal(prev.state)) return { action_id: id, wait: { kind: "action", action_id: id } };
    return { result: actionResult(prev), action_id: id };
  }
  const mode = await getAutonomy(env, ctx.hostId);
  if (mode === "paused") return { error: "autonomy is paused: AI actions are disabled" };
  const req = { action, params, reason };
  const [endpoints, thresholds] = await Promise.all([getServerEndpoints(env), effectiveThresholds(env, ctx.hostId)]);
  const gctx = await buildGateContext(env, { hostId: ctx.hostId, source: "ai", mode, thresholds, serverEndpoints: endpoints, requests: [req] });
  const d = gateBatch([req], gctx)[0]!;
  if (!d.accepted) {
    const raw = truncate(JSON.stringify(params ?? {}), 2000);
    await createAction(env, {
      id, incident_id: ctx.incidentId, host_id: ctx.hostId, action: action.slice(0, 64),
      params: Object.keys(d.normalizedParams).length ? d.normalizedParams : safeJson<Record<string, unknown>>(raw, { _truncated: raw }),
      tier: d.tier, kind: d.kind, state: "rejected", proposed_by: "ai", rationale: reason, reject_reason: d.reason,
    });
    await audit(env, { actor: "ai", event: "gate.rejected", incident_id: ctx.incidentId, host_id: ctx.hostId, action_id: id, detail: { action, reason: d.reason } });
    return { error: `gate rejected: ${d.reason}`, action_id: id };
  }
  if (d.tier === 1) {
    if (!opts.propose) return { error: `${action} is tier 1: use propose_action` };
    return proposeTier1(ctx, id, d.action, d.normalizedParams, d.kind, reason);
  }
  if (d.requiresApproval) {
    // propose_only mode: tier-0 actions also wait for a human
    const row = await createAction(env, { id, incident_id: ctx.incidentId, host_id: ctx.hostId, action: d.action, params: d.normalizedParams, tier: 0, kind: d.kind, state: "proposed", proposed_by: "ai", rationale: reason, expires_at: new Date(Date.now() + PROPOSAL_TTL_S * 1000).toISOString() });
    return { result: { status: "proposed", note: "propose_only mode: a human must approve; call wait_for_approvals" }, action_id: row.id };
  }
  const row = await createAction(env, { id, incident_id: ctx.incidentId, host_id: ctx.hostId, action: d.action, params: d.normalizedParams, tier: 0, kind: d.kind, state: "approved", proposed_by: "ai", rationale: reason });
  const after = await dispatchAction(env, row, "ai");
  if (d.kind === "command" && !isTerminal(after.state)) return { action_id: id, wait: { kind: "action", action_id: id } };
  return { result: actionResult(after), action_id: id };
}

export function actionResult(a: ActionRow): Record<string, unknown> {
  return { action: a.action, state: a.state, result: safeJson(a.result_json, null), error: a.error };
}

async function proposeTier1(ctx: ToolCtx, id: string, action: string, params: Record<string, unknown>, kind: "command" | "policy", reason: string): Promise<ToolOutcome> {
  const { env } = ctx;
  const key = (await sha256Hex(action + stableStringify(params))).slice(0, 16);
  const prior = await env.DB.prepare("SELECT 1 AS x FROM audit_log WHERE incident_id=? AND event='critic.revise' AND detail_json LIKE ? LIMIT 1").bind(ctx.incidentId, `%"key":"${key}"%`).first();
  const anomalies = (await env.DB.prepare("SELECT * FROM anomalies WHERE incident_id=? ORDER BY ts LIMIT 10").bind(ctx.incidentId).all<AnomalyRow>()).results;
  const toolRows = (await env.DB.prepare("SELECT tool_name, content_json FROM agent_turns WHERE run_id=? AND role='tool' ORDER BY seq").bind(ctx.runId).all<{ tool_name: string; content_json: string }>()).results;
  // Drop base64 copies so the readable text (e.g. a sampled file) fits; 400 chars cut it off and the critic thought nothing was sampled.
  const toolsRun = toolRows.map((t) => ({ tool: t.tool_name, summary: truncate(t.content_json.replace(/"base64":"[^"]*",?/g, ""), 1200) }));
  const notes = await critique(env, { proposal: { action, params, reason }, anomalies, toolsRun }, prior ? 1 : 0);
  if (notes.decision === "revise" && !prior) {
    await audit(env, { actor: "ai", event: "critic.revise", incident_id: ctx.incidentId, host_id: ctx.hostId, detail: { key, action, missing_checks: notes.missing_checks, concerns: notes.concerns } });
    return { result: { status: "revision_requested", note: "Nothing was submitted. A reviewer asks you to run these checks, then call propose_action again with the same action and params.", missing_checks: notes.missing_checks, concerns: notes.concerns } };
  }
  const final: CriticNotes = { ...notes, decision: "submit" };
  const row = await createAction(env, { id, incident_id: ctx.incidentId, host_id: ctx.hostId, action, params, tier: 1, kind, state: "proposed", proposed_by: "ai", rationale: reason, expires_at: new Date(Date.now() + PROPOSAL_TTL_S * 1000).toISOString(), critic: final });
  await audit(env, { actor: "ai", event: "critic.submit", incident_id: ctx.incidentId, host_id: ctx.hostId, action_id: id, detail: { key, action, concerns: final.concerns, round: final.round } });
  return { result: { status: "submitted for human approval", note: "Call wait_for_approvals to learn the outcome.", critic: { concerns: final.concerns } }, action_id: row.id };
}

// ---------- waiting (driven by the workflow) ----------
export async function actionState(env: Env, id: string): Promise<string> {
  return (await getAction(env, id))?.state ?? "missing";
}

export async function pendingApprovedIds(env: Env, incidentId: string): Promise<string[]> {
  return (await env.DB.prepare("SELECT id FROM actions WHERE incident_id=? AND proposed_by='ai' AND tier=1 AND state='dispatched' ORDER BY created_at").bind(incidentId).all<{ id: string }>()).results.map((r) => r.id);
}

export async function proposalOutcomes(env: Env, incidentId: string, decidedSinceIso?: string): Promise<unknown[]> {
  const rows = (await env.DB.prepare(
    "SELECT * FROM actions WHERE incident_id=? AND proposed_by='ai' AND tier=1 AND NOT (state='rejected' AND approved_by IS NULL)" +
      (decidedSinceIso ? " AND state!='proposed' AND created_at>=?" : "") + " ORDER BY created_at",
  ).bind(...(decidedSinceIso ? [incidentId, decidedSinceIso] : [incidentId])).all<ActionRow>()).results;
  return rows.map((a) => ({ action_id: a.id, action: a.action, params: safeJson(a.params_json, {}), state: a.state, approved_by: a.approved_by, reject_reason: a.reject_reason, result: safeJson(a.result_json, null), error: a.error }));
}

/** Build the final tool result once a wait is over. */
export async function completeWait(env: Env, incidentId: string, wait: WaitSpec): Promise<ToolOutcome> {
  if (wait.kind === "action") {
    const a = await getAction(env, wait.action_id);
    if (!a) return { error: "action vanished" };
    if (!isTerminal(a.state)) return { error: `no result from the host yet (state=${a.state})`, action_id: a.id };
    return { result: actionResult(a), action_id: a.id };
  }
  const outcomes = await proposalOutcomes(env, incidentId);
  return { result: { proposals: outcomes, note: outcomes.length ? undefined : "no proposals for this incident" } };
}

// ---------- server read-only tools ----------
const likeEsc = (v: string) => v.replace(/[\\%_]/g, (c) => "\\" + c);

async function fleetSearch(ctx: ToolCtx, a: { type: string; value: string }): Promise<ToolOutcome> {
  const v = a.value.trim();
  const ok =
    a.type === "ip" ? !!parseIp(v)
    : a.type === "sha256" ? /^[0-9a-fA-F]{64}$/.test(v)
    : a.type === "domain" ? /^[A-Za-z0-9._\-]{1,253}$/.test(v)
    : a.type === "path" ? v.startsWith("/") && v.length <= 512
    : v.length >= 1 && v.length <= 128;
  if (!ok) return { error: `value is not a valid ${a.type}` };
  const db = ctx.env.DB;
  const rows =
    a.type === "rule_id"
      ? (await db.prepare("SELECT a.id, a.host_id, h.hostname, a.ts, a.rule_id, a.severity, a.summary FROM anomalies a LEFT JOIN hosts h ON h.id=a.host_id WHERE a.host_id!=? AND a.rule_id=? ORDER BY a.ts DESC LIMIT ?").bind(ctx.hostId, v, SERVER_ROW_CAP).all()).results
      : (await db.prepare("SELECT a.id, a.host_id, h.hostname, a.ts, a.rule_id, a.severity, a.summary FROM anomalies a LEFT JOIN hosts h ON h.id=a.host_id WHERE a.host_id!=? AND (a.evidence_json LIKE ? ESCAPE '\\' OR a.summary LIKE ? ESCAPE '\\') ORDER BY a.ts DESC LIMIT ?").bind(ctx.hostId, `%${likeEsc(v)}%`, `%${likeEsc(v)}%`, SERVER_ROW_CAP).all()).results;
  const iocs = a.type === "path" || a.type === "rule_id" ? [] : (await db.prepare("SELECT type, value, source, incident_id, first_seen FROM iocs WHERE type=? AND value=? LIMIT 10").bind(a.type, a.type === "sha256" ? v.toLowerCase() : v).all()).results;
  return { result: { other_hosts_matches: rows, known_iocs: iocs, note: "searches inline evidence and summaries of OTHER hosts; capped at 50 rows" } };
}

// ---------- the table ----------
const KINDS = ["process_tree", "open_files", "netconns", "file_hash", "log_excerpt", "user_info", "file_sample"] as const;

export const TOOLS: ToolDef[] = [
  def("collect_evidence", "host", "Collect evidence from the host. kind: process_tree|open_files|netconns (target = pid), file_hash|file_sample (target = absolute path), user_info (target = username), log_excerpt (target = auth.log|secure|syslog|messages|kern.log|audit/audit.log|journal|journal:<unit>). Waits for the result.",
    z.object({ kind: z.enum(KINDS), target: z.string().optional() }), (c, a) => execGated(c, "collect_evidence", a, "collect_evidence", { propose: false })),
  def("test_rule", "host", "Test a Sigma rule against the host's recent events. Waits for the result.",
    z.object({ yaml: z.string() }), (c, a) => execGated(c, "test_rule", a, "test_rule", { propose: false })),
  def("yara_scan", "host", "Scan an absolute file path with YARA on the host. Waits for the result.",
    z.object({ path: z.string(), rules: z.string().optional() }), (c, a) => execGated(c, "yara_scan", a, "yara_scan", { propose: false })),
  def("add_watch", "policy", "Add a detection watch on the host (path: absolute path, process: name, port: 1-65535).",
    z.object({ kind: z.enum(["path", "process", "port"]), target: z.string() }), (c, a) => execGated(c, "add_watch", a, "add_watch", { propose: false })),
  def("adjust_threshold", "policy", "Adjust a detection threshold within 3x of its current value.",
    z.object({ key: z.string(), value: z.number() }), (c, a) => execGated(c, "adjust_threshold", a, "adjust_threshold", { propose: false })),
  def("propose_rule", "policy", "Propose a new Sigma rule (deployed in shadow mode only).",
    z.object({ title: z.string(), yaml: z.string() }), (c, a) => execGated(c, "propose_rule", a, "propose_rule", { propose: false })),
  def("raise_log_level", "policy", "Raise the host agent's log level to debug for a limited time.",
    z.object({ ttl_seconds: z.number().optional() }), (c, a) => execGated(c, "raise_log_level", a, "raise_log_level", { propose: false })),
  def("propose_action", "propose", "Propose a disruptive tier-1 action for human approval: kill_process {pid, start_time?}, block_ip {ip, ttl_seconds}, quarantine_file {path}, disable_user {username}, isolate_host {ttl_seconds}, promote_rule {rule_id}, suppress {fingerprint, ttl_seconds, reason}, disable_rule {rule_id}. A reviewer may ask for more checks first (nothing is submitted then); resubmit after running them.",
    z.object({ action: z.string(), params: z.record(z.string(), z.unknown()), reason: z.string() }),
    (c, a) => execGated(c, a.action, a.params, truncate(a.reason, 1000), { propose: true })),
  def("wait_for_approvals", "approvals", "Wait until a human decides on your pending proposals (can take minutes to hours). Returns each proposal's outcome: state, approved_by, reject_reason, result or error.",
    z.object({}), async () => ({ wait: { kind: "approvals" } })),
  def("host_timeline", "server", "Recent anomalies, actions and incidents on this host. since: ISO timestamp (default: last 24h).",
    z.object({ since: z.string().optional() }),
    async (c, a) => {
      const t = a.since ? Date.parse(a.since) : Date.now() - 86_400_000;
      if (Number.isNaN(t)) return { error: "since must be an ISO timestamp" };
      const since = new Date(t).toISOString();
      const db = c.env.DB;
      const [an, ac, inc] = await Promise.all([
        db.prepare("SELECT ts, rule_id, severity, summary FROM anomalies WHERE host_id=? AND ts>=? ORDER BY ts DESC LIMIT ?").bind(c.hostId, since, SERVER_ROW_CAP).all(),
        db.prepare("SELECT created_at, action, state, proposed_by, incident_id FROM actions WHERE host_id=? AND created_at>=? ORDER BY created_at DESC LIMIT ?").bind(c.hostId, since, 30).all(),
        db.prepare("SELECT id, title, status, severity, verdict, created_at FROM incidents WHERE host_id=? AND created_at>=? ORDER BY created_at DESC LIMIT 10").bind(c.hostId, since).all(),
      ]);
      return { result: { anomalies: an.results, actions: ac.results, incidents: inc.results } };
    }),
  def("fleet_search", "server", "Search OTHER hosts' anomalies (evidence/summary) and known IOCs for an indicator. type: ip|sha256|domain|path|rule_id. Max 50 rows.",
    z.object({ type: z.enum(["ip", "sha256", "domain", "path", "rule_id"]), value: z.string() }), fleetSearch),
  def("similar_incidents", "server", "Find similar past incidents (with analyst labels when present) by free-text query.",
    z.object({ query: z.string() }), async (c, a) => ({ result: await findSimilar(c.env, truncate(a.query, 2000), c.incidentId) })),
  def("get_rule", "server", "Read a detection rule by id (title, level, status, hit/FP counts, Sigma YAML).",
    z.object({ rule_id: z.string() }),
    async (c, a) => {
      const r = await c.env.DB.prepare("SELECT id, title, level, status, logsource, hits_total, fp_total, tp_total, yaml FROM rules WHERE id=?").bind(a.rule_id.slice(0, 128)).first<Record<string, unknown>>();
      return r ? { result: { ...r, yaml: truncate(String(r.yaml), 6000) } } : { error: "unknown rule" };
    }),
  def("finish", "finish", "End the investigation. verified=true only if, after a successful containment, you re-checked with tools that it held (put what you checked in verification).",
    z.object({
      verdict: z.enum(["benign", "suspicious", "malicious"]),
      severity: z.enum(["info", "low", "medium", "high", "critical"]),
      confidence: z.number().describe("0..1"),
      summary: z.string().min(1).max(6000),
      attack_tags: z.array(z.string().max(100)).max(20).default([]),
      iocs: z.array(z.object({ type: z.enum(["ip", "sha256", "domain"]), value: z.string().min(1).max(253) })).max(50).default([]),
      verified: z.boolean().or(z.enum(["true", "false"]).transform((v) => v === "true")).default(false),
      verification: z.string().max(2000).default(""),
    }),
    async (c, a) => {
      const inc = await getIncident(c.env, c.incidentId);
      if (!inc) return { error: "incident missing" };
      // Finishing with proposals still waiting would leave any later approval unverified.
      const pending = (await c.env.DB.prepare("SELECT COUNT(*) AS n FROM actions WHERE incident_id=? AND state='proposed'").bind(c.incidentId).first<{ n: number }>())?.n ?? 0;
      if (pending > 0) return { error: `${pending} proposal(s) still awaiting human approval: call wait_for_approvals, then verify, then finish` };
      const seq0 = await getTurn(c.env, c.runId, 0);
      const reviewId = await deterministicUuid(`review:${c.incidentId}:${c.runId}:final:0`);
      const confidence = a.confidence > 1 && a.confidence <= 100 ? a.confidence / 100 : Math.min(1, Math.max(0, a.confidence));
      await recordReview(c.env, c.incidentId, {
        reviewId, step: "final", round: 0, model: c.env.AI_MODEL, promptHash: await sha256Hex(`loop\n${seq0?.content_json ?? ""}`),
        output: { verdict: a.verdict, severity: a.severity, confidence, rationale: a.summary, attack_tags: a.attack_tags, iocs: a.iocs, requests: [], verified: a.verified, verification: a.verification },
        auditExtra: { verified: a.verified },
      });
      return { result: { ok: true }, done: true };
    }),
];

export const toolByName = (name: string): ToolDef | undefined => TOOLS.find((t) => t.name === name);

export function toolSpecs(only?: string): ToolSpec[] {
  return TOOLS.filter((t) => !only || t.name === only).map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.json } }));
}

/** Validate and run one tool call. Never throws: bad arguments, gate rejections and handler failures come back as tool errors. */
export async function runTool(ctx: ToolCtx, name: string, args: Record<string, unknown>): Promise<ToolOutcome> {
  const tool = toolByName(name);
  if (!tool) return { error: `unknown tool '${truncate(name, 64)}'. Available: ${TOOLS.map((t) => t.name).join(", ")}` };
  if ("_unparsed" in args) return { error: "arguments were not a valid JSON object" };
  const p = tool.schema.safeParse(args);
  if (!p.success) return { error: "invalid arguments: " + p.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ") };
  try {
    return await tool.handler(ctx, p.data);
  } catch (e) {
    return { error: "tool failed: " + truncate(errMsg(e), 300) };
  }
}


