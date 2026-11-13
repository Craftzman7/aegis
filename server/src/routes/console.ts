import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { ask } from "../ai/analyst";
import { loadContext } from "../ai/context";
import { rememberIncident } from "../ai/memory";
import { createAction, dispatchAction, getAction, getAutonomy, PROPOSAL_TTL_S, setActionState, signalWorkflow } from "../lib/actions";
import { audit } from "../lib/audit";
import { publish } from "../lib/fleet";
import { getIncident, publishIncident } from "../lib/incidents";
import { fleetStub } from "../lib/stubs";
import { deterministicUuid, errMsg, nowIso, parseRow, parseRows, placeholders, randomToken, safeJson, sha256Hex, truncate } from "../lib/util";
import { buildGateContext, gate, type GateRequest } from "../policy/gate";
import { bumpAllHosts, effectiveThresholds, getServerEndpoints, updateHostPolicy } from "../policy/service";
import { incidentToOcsf, iocsToStix, normalizeIoc, parseIocCsv, parseStixBundle } from "../export";
import { lintSigma } from "../sigma/lint";
import type { ActionRow, AnomalyRow, AutonomyMode, HostRow, IncidentRow, RuleRow } from "../types";
import { startOrResumeWorkflow } from "../queue";

type ConsoleEnv = { Bindings: Env; Variables: { email: string } };
export const consoleApp = new Hono<ConsoleEnv>();

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Cloudflare Access JWT verification (or DEV_MODE bypass). */
export const accessAuth: MiddlewareHandler<ConsoleEnv> = async (c, next) => {
  if (c.env.DEV_MODE === "true") {
    c.set("email", "dev@local");
    return next();
  }
  const team = c.env.ACCESS_TEAM_DOMAIN;
  const aud = c.env.ACCESS_AUD;
  if (!team || !aud) return c.json({ error: "Access not configured (ACCESS_TEAM_DOMAIN / ACCESS_AUD)" }, 503);
  const token = c.req.header("Cf-Access-Jwt-Assertion") ?? "";
  if (!token) return c.json({ error: "unauthorized" }, 401);
  try {
    let jwks = jwksCache.get(team);
    if (!jwks) jwksCache.set(team, (jwks = createRemoteJWKSet(new URL(`https://${team}/cdn-cgi/access/certs`))));
    const { payload } = await jwtVerify(token, jwks, { issuer: `https://${team}`, audience: aud });
    const email = (payload.email as string | undefined) ?? (payload.common_name as string | undefined) ?? payload.sub;
    if (!email) return c.json({ error: "unauthorized" }, 401);
    c.set("email", email);
  } catch {
    return c.json({ error: "unauthorized" }, 401);
  }
  return next();
};

consoleApp.use("*", accessAuth);

const human = (c: { get(k: "email"): string }) => `human:${c.get("email")}`;
const ONLINE_MS = 5 * 60_000;

async function body<T extends z.ZodTypeAny>(c: { req: { json(): Promise<unknown> } }, schema: T): Promise<z.infer<T> | null> {
  try {
    const r = schema.safeParse(await c.req.json());
    return r.success ? r.data : null;
  } catch {
    return null;
  }
}
const bad = (c: { json(o: unknown, s: 400): Response }, msg = "invalid request body") => c.json({ error: msg }, 400);

// ---------------- live feed ----------------
consoleApp.get("/live", async (c) => {
  if (c.req.header("Upgrade")?.toLowerCase() !== "websocket") return c.json({ error: "websocket upgrade required" }, 426);
  return fleetStub(c.env).fetch(c.req.raw);
});

const api = new Hono<ConsoleEnv>();

api.get("/me", (c) => c.json({ email: c.get("email") }));

api.get("/overview", async (c) => {
  const db = c.env.DB;
  const now = Date.now();
  const hosts = (await db.prepare("SELECT status, last_seen FROM hosts").all<{ status: string; last_seen: string | null }>()).results;
  let online = 0, offline = 0, isolated = 0;
  for (const h of hosts) {
    if (h.status === "isolated") isolated++;
    else if (h.last_seen && now - Date.parse(h.last_seen) < ONLINE_MS) online++;
    else offline++;
  }
  const sev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of (await db.prepare("SELECT severity, COUNT(*) AS n FROM incidents WHERE status NOT LIKE 'closed%' GROUP BY severity").all<{ severity: string; n: number }>()).results) sev[r.severity] = r.n;
  const pending = (await db.prepare("SELECT COUNT(*) AS n FROM actions WHERE state='proposed'").first<{ n: number }>())?.n ?? 0;
  const since = new Date(now - 24 * 3600_000);
  since.setMinutes(0, 0, 0);
  const buckets = new Map<string, number>();
  for (let i = 0; i < 25; i++) buckets.set(new Date(since.getTime() + i * 3600_000).toISOString().slice(0, 13), 0);
  for (const r of (await db.prepare("SELECT substr(ts,1,13) AS h, COUNT(*) AS n FROM anomalies WHERE ts>=? AND shadow=0 GROUP BY h").bind(since.toISOString()).all<{ h: string; n: number }>()).results)
    if (buckets.has(r.h)) buckets.set(r.h, r.n);
  const aiActions = (await db.prepare("SELECT COUNT(*) AS n FROM actions WHERE proposed_by='ai' AND state!='rejected' AND created_at>=?").bind(new Date(now - 24 * 3600_000).toISOString()).first<{ n: number }>())?.n ?? 0;
  const mode = (await db.prepare("SELECT value FROM settings WHERE key='autonomy'").first<{ value: string }>())?.value ?? "autonomous";
  return c.json({
    hosts: { total: hosts.length, online, offline, isolated },
    incidents_by_severity: sev,
    pending_approvals: pending,
    anomalies_24h_hourly: [...buckets].map(([h, count]) => ({ hour: `${h}:00:00.000Z`, count })),
    ai_actions_24h: aiActions,
    autonomy: mode,
  });
});

// ---------------- hosts ----------------
api.get("/hosts", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT * FROM hosts ORDER BY hostname").all<HostRow>()).results;
  const now = Date.now();
  return c.json(rows.map((h) => ({ ...parseRow(h as unknown as Record<string, unknown>), online: !!h.last_seen && now - Date.parse(h.last_seen) < ONLINE_MS })));
});

api.get("/hosts/:id", async (c) => {
  const id = c.req.param("id");
  const host = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(id).first<HostRow>();
  if (!host) return c.json({ error: "not found" }, 404);
  const db = c.env.DB;
  const [an, inc, act, pol] = await Promise.all([
    db.prepare("SELECT * FROM anomalies WHERE host_id=? ORDER BY ts DESC LIMIT 50").bind(id).all<AnomalyRow>(),
    db.prepare("SELECT * FROM incidents WHERE host_id=? ORDER BY updated_at DESC LIMIT 25").bind(id).all<IncidentRow>(),
    db.prepare("SELECT * FROM actions WHERE host_id=? ORDER BY created_at DESC LIMIT 50").bind(id).all<ActionRow>(),
    db.prepare("SELECT * FROM policies WHERE host_id=? ORDER BY version DESC LIMIT 1").bind(id).first<Record<string, unknown>>(),
  ]);
  return c.json({
    host: { ...parseRow(host as unknown as Record<string, unknown>), online: !!host.last_seen && Date.now() - Date.parse(host.last_seen) < ONLINE_MS },
    anomalies: parseRows(an.results),
    incidents: parseRows(inc.results),
    actions: parseRows(act.results),
    policy: pol ? parseRow(pol) : null,
  });
});

const ModeSchema = z.enum(["autonomous", "propose_only", "paused"]);

async function resumePausedIncidents(env: Env): Promise<void> {
  const rows = (await env.DB.prepare("SELECT * FROM incidents WHERE workflow_id IS NULL AND status='open'").all<IncidentRow>()).results;
  for (const inc of rows) {
    if ((await getAutonomy(env, inc.host_id)) !== "paused") await startOrResumeWorkflow(env, inc);
  }
}

api.post("/hosts/:id/autonomy", async (c) => {
  const b = await body(c, z.object({ mode: ModeSchema.nullable() }));
  if (!b) return bad(c);
  const id = c.req.param("id");
  const res = await c.env.DB.prepare("UPDATE hosts SET autonomy=? WHERE id=?").bind(b.mode, id).run();
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  await audit(c.env, { actor: human(c), event: "autonomy.host", host_id: id, detail: { mode: b.mode } });
  const row = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(id).first<Record<string, unknown>>();
  if (row) await publish(c.env, "host", row);
  c.executionCtx.waitUntil(resumePausedIncidents(c.env));
  return c.json({ ok: true, mode: b.mode });
});

api.get("/settings/autonomy", async (c) => c.json({ mode: (await c.env.DB.prepare("SELECT value FROM settings WHERE key='autonomy'").first<{ value: string }>())?.value ?? "autonomous" }));
api.post("/settings/autonomy", async (c) => {
  const b = await body(c, z.object({ mode: ModeSchema }));
  if (!b) return bad(c);
  await c.env.DB.prepare("INSERT INTO settings(key,value) VALUES('autonomy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(b.mode).run();
  await audit(c.env, { actor: human(c), event: "autonomy.global", detail: { mode: b.mode } });
  c.executionCtx.waitUntil(resumePausedIncidents(c.env));
  return c.json({ ok: true, mode: b.mode });
});

// ---------------- incidents ----------------
api.get("/incidents", async (c) => {
  const w: string[] = [];
  const b: unknown[] = [];
  const status = c.req.query("status");
  const severity = c.req.query("severity");
  const host = c.req.query("host");
  if (status) { w.push("status=?"); b.push(status); }
  if (severity) { w.push("severity=?"); b.push(severity); }
  if (host) { w.push("host_id=?"); b.push(host); }
  const limit = Math.min(500, Math.max(1, Number(c.req.query("limit") ?? 200) || 200));
  const rows = (await c.env.DB.prepare(`SELECT * FROM incidents ${w.length ? "WHERE " + w.join(" AND ") : ""} ORDER BY updated_at DESC LIMIT ?`).bind(...b, limit).all<IncidentRow>()).results;
  return c.json(parseRows(rows));
});

api.get("/incidents/:id", async (c) => {
  const id = c.req.param("id");
  const incident = await getIncident(c.env, id);
  if (!incident) return c.json({ error: "not found" }, 404);
  const db = c.env.DB;
  const [an, rev, act, aud, turns] = await Promise.all([
    db.prepare("SELECT * FROM anomalies WHERE incident_id=? ORDER BY ts").bind(id).all<AnomalyRow>(),
    db.prepare("SELECT * FROM ai_reviews WHERE incident_id=? ORDER BY ts").bind(id).all<Record<string, unknown>>(),
    db.prepare("SELECT * FROM actions WHERE incident_id=? ORDER BY created_at").bind(id).all<ActionRow>(),
    db.prepare("SELECT * FROM audit_log WHERE incident_id=? ORDER BY id").bind(id).all<Record<string, unknown>>(),
    db.prepare("SELECT * FROM agent_turns WHERE incident_id=? ORDER BY run_id, seq").bind(id).all<Record<string, unknown>>(),
  ]);
  return c.json({ incident: parseRow(incident as unknown as Record<string, unknown>), anomalies: parseRows(an.results), reviews: parseRows(rev.results), actions: parseRows(act.results), audit: parseRows(aud.results), turns: parseRows(turns.results) });
});

api.post("/incidents/:id/verdict", async (c) => {
  const b = await body(c, z.object({ verdict: z.enum(["true_positive", "false_positive"]), note: z.string().max(4000).default("") }));
  if (!b) return bad(c);
  const id = c.req.param("id");
  const inc = await getIncident(c.env, id);
  if (!inc) return c.json({ error: "not found" }, 404);
  const now = nowIso();
  const status = b.verdict === "true_positive" ? "closed_tp" : "closed_benign";
  await c.env.DB.prepare("UPDATE incidents SET verdict=?, status=?, analyst_note=?, closed_at=?, updated_at=? WHERE id=?").bind(b.verdict, status, b.note, now, now, id).run();
  // rule stats
  const rules = (await c.env.DB.prepare("SELECT DISTINCT rule_id FROM anomalies WHERE incident_id=?").bind(id).all<{ rule_id: string }>()).results.map((r) => r.rule_id);
  if (rules.length) {
    const col = b.verdict === "true_positive" ? "tp_total" : "fp_total";
    await c.env.DB.prepare(`UPDATE rules SET ${col}=${col}+1 WHERE id IN (${placeholders(rules.length)})`).bind(...rules).run();
  }
  if (b.verdict === "true_positive") {
    // A human confirmed it: now it is safe to push this incident's IOCs to agents.
    const res = await c.env.DB.prepare("UPDATE iocs SET watch=1 WHERE incident_id=? AND watch=0").bind(id).run();
    if (res.meta.changes) c.executionCtx.waitUntil(bumpAllHosts(c.env, human(c), `IOCs from incident ${id} confirmed`));
  }
  // close workflow
  if (inc.workflow_id) {
    try {
      await (await c.env.INVESTIGATION.get(inc.workflow_id)).terminate();
    } catch {
      await signalWorkflow(c.env, id, "approval", { closed: true });
    }
  }
  // expire outstanding proposals
  const open = (await c.env.DB.prepare("SELECT id FROM actions WHERE incident_id=? AND state='proposed'").bind(id).all<{ id: string }>()).results;
  for (const a of open) await setActionState(c.env, a.id, "expired", { error: "incident closed by analyst" });
  await audit(c.env, { actor: human(c), event: "incident.verdict", incident_id: id, host_id: inc.host_id, detail: { verdict: b.verdict, note: b.note } });
  const updated = (await getIncident(c.env, id))!;
  await publishIncident(c.env, id);
  c.executionCtx.waitUntil(
    rememberIncident(
      c.env,
      { incident_id: id, host_id: inc.host_id, title: truncate(inc.title, 200), verdict: b.verdict, label: b.verdict, severity: inc.severity, summary: truncate(`${inc.ai_summary ?? inc.title} | analyst: ${b.note}`, 600), rule_ids: rules.join(",").slice(0, 500) },
      `${inc.title}\n${inc.ai_summary ?? ""}\n${b.note}`,
    ),
  );
  return c.json({ incident: parseRow(updated as unknown as Record<string, unknown>) });
});

api.post("/incidents/:id/ask", async (c) => {
  const b = await body(c, z.object({ question: z.string().min(1).max(4000) }));
  if (!b) return bad(c);
  const id = c.req.param("id");
  if (!(await getIncident(c.env, id))) return c.json({ error: "not found" }, 404);
  try {
    const ctx = await loadContext(c.env, id, "reanalyze", 0);
    const { answer, promptHash } = await ask(c.env, ctx, b.question);
    const rid = crypto.randomUUID();
    await c.env.DB.prepare("INSERT INTO ai_reviews(id, incident_id, step, round, model, prompt_hash, output_json, gate_json, ts) VALUES (?,?,'ask',0,?,?,?,NULL,?)")
      .bind(rid, id, c.env.AI_MODEL, promptHash, JSON.stringify({ question: b.question, answer, asked_by: c.get("email") }), nowIso()).run();
    await audit(c.env, { actor: human(c), event: "incident.ask", incident_id: id, detail: { question: truncate(b.question, 300) } });
    return c.json({ answer });
  } catch (e) {
    return c.json({ error: "analyst unavailable: " + errMsg(e) }, 502);
  }
});

// ---------------- approvals & actions ----------------
api.get("/approvals", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT * FROM actions WHERE state='proposed' ORDER BY created_at DESC LIMIT 200").all<ActionRow>()).results;
  const out = [];
  for (const a of rows) {
    const inc = a.incident_id ? await getIncident(c.env, a.incident_id) : null;
    const host = await c.env.DB.prepare("SELECT id, hostname, os, status, last_seen FROM hosts WHERE id=?").bind(a.host_id).first<Record<string, unknown>>();
    out.push({ ...parseRow(a as unknown as Record<string, unknown>), incident: inc ? parseRow(inc as unknown as Record<string, unknown>) : null, host });
  }
  return c.json(out);
});

async function humanGate(env: Env, hostId: string, req: GateRequest) {
  const [mode, endpoints, thresholds] = await Promise.all([getAutonomy(env, hostId), getServerEndpoints(env), effectiveThresholds(env, hostId)]);
  const ctx = await buildGateContext(env, { hostId, source: "human", mode, thresholds, serverEndpoints: endpoints, requests: [req] });
  // Humans re-submitting identical params to an already-proposed action must not trip the duplicate check.
  ctx.openKeys = new Set();
  return gate(req, ctx);
}

api.post("/actions/:id/approve", async (c) => {
  const b = (await body(c, z.object({ params: z.record(z.string(), z.unknown()).optional(), ttl_seconds: z.number().int().positive().optional() }))) ?? null;
  const id = c.req.param("id");
  const a = await getAction(c.env, id);
  if (!a) return c.json({ error: "not found" }, 404);
  if (a.state !== "proposed") return c.json({ error: `action is ${a.state}, not proposed` }, 409);
  let params = safeJson<Record<string, unknown>>(a.params_json, {});
  if (b?.params) params = b.params;
  if (b?.ttl_seconds !== undefined) {
    if (!("ttl_seconds" in params) && !["block_ip", "isolate_host", "raise_log_level", "suppress"].includes(a.action)) return c.json({ error: "action has no ttl" }, 400);
    params = { ...params, ttl_seconds: b.ttl_seconds };
  }
  // Modified params are re-validated by the gate (bounds still apply to humans).
  const d = await humanGate(c.env, a.host_id, { action: a.action, params });
  if (!d.accepted) return c.json({ error: `gate rejected: ${d.reason}` }, 422);
  await c.env.DB.prepare("UPDATE actions SET params_json=?, state='approved', approved_by=?, updated_at=? WHERE id=? AND state='proposed'").bind(JSON.stringify(d.normalizedParams), human(c), nowIso(), id).run();
  await audit(c.env, { actor: human(c), event: "action.approved", incident_id: a.incident_id, host_id: a.host_id, action_id: id, detail: { action: a.action, params: d.normalizedParams } });
  const row = await dispatchAction(c.env, (await getAction(c.env, id))!, human(c));
  await signalWorkflow(c.env, a.incident_id, "approval", { action_id: id, decision: "approved", by: c.get("email") });
  return c.json(parseRow(row as unknown as Record<string, unknown>));
});

api.post("/actions/:id/reject", async (c) => {
  const b = await body(c, z.object({ reason: z.string().max(2000).default("") }));
  if (!b) return bad(c);
  const id = c.req.param("id");
  const a = await getAction(c.env, id);
  if (!a) return c.json({ error: "not found" }, 404);
  if (a.state !== "proposed") return c.json({ error: `action is ${a.state}, not proposed` }, 409);
  const row = await setActionState(c.env, id, "rejected", { reject_reason: b.reason || "rejected by analyst", approved_by: human(c) });
  await audit(c.env, { actor: human(c), event: "action.rejected", incident_id: a.incident_id, host_id: a.host_id, action_id: id, detail: { reason: b.reason } });
  await signalWorkflow(c.env, a.incident_id, "approval", { action_id: id, decision: "rejected", by: c.get("email"), reason: b.reason });
  return c.json(parseRow(row as unknown as Record<string, unknown>));
});

api.post("/actions/:id/rollback", async (c) => {
  const id = c.req.param("id");
  const a = await getAction(c.env, id);
  if (!a) return c.json({ error: "not found" }, 404);
  if (a.state !== "succeeded" || !a.rollback_token) return c.json({ error: "only succeeded actions with a rollback_token can be rolled back" }, 409);
  const rid = await deterministicUuid(`rollback:${id}`);
  if (await getAction(c.env, rid)) return c.json({ error: "rollback already requested" }, 409);
  const row = await createAction(c.env, {
    id: rid, incident_id: a.incident_id, host_id: a.host_id, action: "rollback", params: { rollback_token: a.rollback_token }, tier: 0, kind: "command",
    state: "approved", proposed_by: human(c), approved_by: human(c), rationale: `rollback of ${a.action} ${a.id}`, rollback_of: a.id,
  });
  const out = await dispatchAction(c.env, row, human(c));
  return c.json(parseRow(out as unknown as Record<string, unknown>));
});

api.post("/actions", async (c) => {
  const b = await body(c, z.object({ host_id: z.string(), action: z.string(), params: z.record(z.string(), z.unknown()).default({}), incident_id: z.string().optional() }));
  if (!b) return bad(c);
  if (!(await c.env.DB.prepare("SELECT 1 AS x FROM hosts WHERE id=?").bind(b.host_id).first())) return c.json({ error: "unknown host" }, 404);
  const d = await humanGate(c.env, b.host_id, { action: b.action, params: b.params });
  if (!d.accepted) {
    await audit(c.env, { actor: human(c), event: "gate.rejected", host_id: b.host_id, incident_id: b.incident_id, detail: { action: b.action, reason: d.reason } });
    return c.json({ error: `gate rejected: ${d.reason}` }, 422);
  }
  const row = await createAction(c.env, {
    id: crypto.randomUUID(), incident_id: b.incident_id ?? null, host_id: b.host_id, action: d.action, params: d.normalizedParams, tier: d.tier, kind: d.kind,
    state: "approved", proposed_by: human(c), approved_by: human(c), rationale: "manual action",
  });
  const out = await dispatchAction(c.env, row, human(c));
  return c.json(parseRow(out as unknown as Record<string, unknown>));
});

api.get("/audit", async (c) => {
  const w: string[] = [];
  const b: unknown[] = [];
  const before = Number(c.req.query("before"));
  if (Number.isInteger(before) && before > 0) { w.push("id<?"); b.push(before); }
  const actor = c.req.query("actor");
  if (actor) { w.push("actor LIKE ? ESCAPE '\\'"); b.push(actor.replace(/[%_\\]/g, "\\$&") + "%"); }
  const event = c.req.query("event");
  if (event) { w.push("event LIKE ? ESCAPE '\\'"); b.push(event.replace(/[%_\\]/g, "\\$&") + "%"); }
  for (const k of ["incident_id", "host_id"] as const) {
    const v = c.req.query(k);
    if (v) { w.push(`${k}=?`); b.push(v); }
  }
  const limit = Math.min(500, Math.max(1, Number(c.req.query("limit") ?? 100) || 100));
  const rows = (await c.env.DB.prepare(`SELECT * FROM audit_log ${w.length ? "WHERE " + w.join(" AND ") : ""} ORDER BY id DESC LIMIT ?`).bind(...b, limit).all<Record<string, unknown>>()).results;
  return c.json(parseRows(rows));
});

// ---------------- rules ----------------
api.get("/rules", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT * FROM rules ORDER BY pack_id, title").all<RuleRow>()).results;
  return c.json(rows.map((r) => {
    const o = parseRow(r as unknown as Record<string, unknown>);
    if (r.pack_id === "sigmahq" && c.req.query("yaml") !== "all") {
      delete o.yaml;
      o.has_yaml = true;
    }
    return o;
  }));
});
api.get("/rules/packs", async (c) => c.json((await c.env.DB.prepare("SELECT * FROM rule_packs").all()).results));

api.post("/rules/lint", async (c) => {
  const b = await body(c, z.object({ yaml: z.string() }));
  if (!b) return bad(c);
  const r = lintSigma(b.yaml);
  return c.json({ ok: r.ok, errors: r.errors });
});

api.post("/rules", async (c) => {
  const b = await body(c, z.object({ yaml: z.string(), status: z.enum(["active", "shadow", "disabled"]).default("shadow") }));
  if (!b) return bad(c);
  const lint = lintSigma(b.yaml);
  if (!lint.ok || !lint.rule) return c.json({ ok: false, errors: lint.errors }, 422);
  const r = lint.rule;
  const now = nowIso();
  const existing = await c.env.DB.prepare("SELECT pack_id FROM rules WHERE id=?").bind(r.id).first<{ pack_id: string }>();
  if (existing && existing.pack_id !== "custom") return c.json({ error: "rule id belongs to another pack; use /rules/:id/status" }, 409);
  await c.env.DB.prepare(
    `INSERT INTO rules(id, pack_id, title, level, logsource, attack_tags_json, yaml, status, created_by, shadow_since, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(id) DO UPDATE SET title=excluded.title, level=excluded.level, logsource=excluded.logsource, attack_tags_json=excluded.attack_tags_json, yaml=excluded.yaml, status=excluded.status, updated_at=excluded.updated_at`,
  ).bind(r.id, "custom", r.title, r.level, r.logsource, JSON.stringify(r.tags), b.yaml, b.status, human(c), b.status === "shadow" ? now : null, now, now).run();
  await audit(c.env, { actor: human(c), event: "rule.saved", detail: { rule_id: r.id, status: b.status } });
  c.executionCtx.waitUntil(bumpAllHosts(c.env, human(c), `rule ${r.id} saved (${b.status})`));
  return c.json(parseRow((await c.env.DB.prepare("SELECT * FROM rules WHERE id=?").bind(r.id).first<RuleRow>()) as unknown as Record<string, unknown>));
});

async function testRuleOnHost(c: { env: Env; get(k: "email"): string }, hostId: string, yaml: string) {
  const lint = lintSigma(yaml);
  if (!lint.ok) return { status: 422, body: { ok: false, errors: lint.errors } };
  if (!(await c.env.DB.prepare("SELECT 1 AS x FROM hosts WHERE id=?").bind(hostId).first())) return { status: 404, body: { error: "unknown host" } };
  const d = await humanGate(c.env, hostId, { action: "test_rule", params: { yaml } });
  if (!d.accepted) return { status: 422, body: { error: d.reason } };
  const row = await createAction(c.env, { id: crypto.randomUUID(), incident_id: null, host_id: hostId, action: "test_rule", params: d.normalizedParams, tier: 0, kind: "command", state: "approved", proposed_by: human(c), approved_by: human(c), rationale: "rule backtest" });
  let cur = await dispatchAction(c.env, row, human(c));
  for (let i = 0; i < 20 && cur.state === "dispatched"; i++) {
    await new Promise((r) => setTimeout(r, 500));
    cur = (await getAction(c.env, row.id))!;
  }
  return { status: 200, body: { action_id: row.id, state: cur.state, result: safeJson(cur.result_json, null), error: cur.error } };
}

// NOTE: registered before /rules/:id/... so "draft" is not taken as an id.
api.post("/rules/draft/test", async (c) => {
  const b = await body(c, z.object({ host_id: z.string(), yaml: z.string() }));
  if (!b) return bad(c);
  const r = await testRuleOnHost(c, b.host_id, b.yaml);
  return c.json(r.body, r.status as 200);
});
api.post("/rules/:id/test", async (c) => {
  const b = await body(c, z.object({ host_id: z.string() }));
  if (!b) return bad(c);
  const rule = await c.env.DB.prepare("SELECT yaml FROM rules WHERE id=?").bind(c.req.param("id")).first<{ yaml: string }>();
  if (!rule) return c.json({ error: "not found" }, 404);
  const r = await testRuleOnHost(c, b.host_id, rule.yaml);
  return c.json(r.body, r.status as 200);
});
api.post("/rules/:id/status", async (c) => {
  const b = await body(c, z.object({ status: z.enum(["active", "shadow", "disabled"]) }));
  if (!b) return bad(c);
  const id = c.req.param("id");
  const now = nowIso();
  const res = await c.env.DB.prepare("UPDATE rules SET status=?, updated_at=?, shadow_since=CASE WHEN ?='shadow' THEN COALESCE(shadow_since, ?) WHEN ?='active' THEN NULL ELSE shadow_since END WHERE id=?").bind(b.status, now, b.status, now, b.status, id).run();
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  await audit(c.env, { actor: human(c), event: "rule.status", detail: { rule_id: id, status: b.status } });
  c.executionCtx.waitUntil(bumpAllHosts(c.env, human(c), `rule ${id} -> ${b.status}`));
  return c.json(parseRow((await c.env.DB.prepare("SELECT * FROM rules WHERE id=?").bind(id).first<RuleRow>()) as unknown as Record<string, unknown>));
});
api.get("/rules/:id", async (c) => {
  const r = await c.env.DB.prepare("SELECT * FROM rules WHERE id=?").bind(c.req.param("id")).first<RuleRow>();
  return r ? c.json(parseRow(r as unknown as Record<string, unknown>)) : c.json({ error: "not found" }, 404);
});

api.get("/coverage", async (c) => {
  const since = new Date(Date.now() - 30 * 86400_000).toISOString();
  const rules = (await c.env.DB.prepare("SELECT id, attack_tags_json FROM rules WHERE status IN ('active','shadow')").all<{ id: string; attack_tags_json: string }>()).results;
  const tech = new Map<string, { rules: Set<string>; hits: number }>();
  const get = (id: string) => tech.get(id) ?? (tech.set(id, { rules: new Set(), hits: 0 }), tech.get(id)!);
  const tid = (t: string) => (/^attack\.t\d{4}(\.\d{3})?$/i.test(t) ? t.slice(7).toUpperCase() : null);
  for (const r of rules) for (const t of safeJson<string[]>(r.attack_tags_json, [])) { const id = tid(t); if (id) get(id).rules.add(r.id); }
  const an = (await c.env.DB.prepare("SELECT attack_tags_json FROM anomalies WHERE ts>=? AND shadow=0 AND attack_tags_json!='[]' LIMIT 20000").bind(since).all<{ attack_tags_json: string }>()).results;
  for (const a of an) for (const t of safeJson<string[]>(a.attack_tags_json, [])) { const id = tid(t); if (id) get(id).hits++; }
  return c.json({ techniques: [...tech].map(([id, v]) => ({ id, rules: v.rules.size, hits_30d: v.hits })).sort((a, b) => a.id.localeCompare(b.id)) });
});

// ---------------- policies ----------------
api.get("/policies/:hostId", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT * FROM policies WHERE host_id=? ORDER BY version DESC LIMIT 100").bind(c.req.param("hostId")).all<Record<string, unknown>>()).results;
  return c.json(parseRows(rows));
});
api.post("/policies/:hostId", async (c) => {
  const b = await body(
    c,
    z.object({
      body: z.object({
        log_level: z.enum(["info", "debug"]).optional(),
        thresholds: z.record(z.string(), z.number().finite()).optional(),
        watches: z.array(z.object({ kind: z.enum(["path", "process", "port"]), target: z.string().min(1).max(256) })).max(500).optional(),
        suppressions: z.array(z.object({ fingerprint: z.string().max(200), expires_at: z.string(), reason: z.string().max(300) })).max(500).optional(),
      }).strict(),
      reason: z.string().max(500).default("manual edit"),
    }),
  );
  if (!b) return bad(c);
  const hostId = c.req.param("hostId");
  if (hostId !== "default" && !(await c.env.DB.prepare("SELECT 1 AS x FROM hosts WHERE id=?").bind(hostId).first())) return c.json({ error: "unknown host" }, 404);
  const version = await updateHostPolicy(c.env, hostId, human(c), b.reason, () => b.body);
  return c.json({ ok: true, version });
});

// ---------------- enrollment, evidence, exports, iocs ----------------
api.post("/enroll-tokens", async (c) => {
  const b = (await body(c, z.object({ ttl_hours: z.number().positive().max(168).default(24) }))) ?? { ttl_hours: 24 };
  const token = `aegis_${randomToken(24)}`;
  const expires = new Date(Date.now() + b.ttl_hours * 3600_000).toISOString();
  await c.env.DB.prepare("INSERT INTO enroll_tokens(token_hash, created_by, expires_at) VALUES (?,?,?)").bind(await sha256Hex(token), c.get("email"), expires).run();
  await audit(c.env, { actor: human(c), event: "enroll_token.created", detail: { expires_at: expires } });
  return c.json({ token, expires_at: expires });
});

api.get("/evidence", async (c) => {
  const key = c.req.query("key") ?? "";
  if (!/^(evidence|digests)\/[A-Za-z0-9_./-]+$/.test(key) || key.includes("..")) return c.json({ error: "invalid key" }, 400);
  const o = await c.env.EVIDENCE.get(key);
  if (!o) return c.json({ error: "not found" }, 404);
  return new Response(o.body, { headers: { "content-type": "application/json", "cache-control": "no-store" } });
});

api.get("/export/incidents/:file", async (c) => {
  const m = /^(.+)\.ocsf\.json$/.exec(c.req.param("file"));
  if (!m) return c.json({ error: "not found" }, 404);
  const inc = await getIncident(c.env, m[1]!);
  if (!inc) return c.json({ error: "not found" }, 404);
  const host = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(inc.host_id).first<HostRow>();
  const an = (await c.env.DB.prepare("SELECT * FROM anomalies WHERE incident_id=? ORDER BY ts").bind(inc.id).all<AnomalyRow>()).results;
  return c.json(incidentToOcsf(inc, host, an));
});
api.get("/export/iocs.stix.json", async (c) => {
  const rows = (await c.env.DB.prepare("SELECT id, type, value, source, first_seen FROM iocs ORDER BY first_seen DESC LIMIT 10000").all<{ id: string; type: string; value: string; source: string; first_seen: string }>()).results;
  return c.json(iocsToStix(rows));
});
api.get("/iocs", async (c) => c.json((await c.env.DB.prepare("SELECT * FROM iocs ORDER BY first_seen DESC LIMIT 1000").all()).results));
api.post("/iocs/:id/watch", async (c) => {
  const b = await body(c, z.object({ watch: z.boolean() }));
  if (!b) return bad(c);
  const res = await c.env.DB.prepare("UPDATE iocs SET watch=? WHERE id=?").bind(b.watch ? 1 : 0, c.req.param("id")).run();
  if (!res.meta.changes) return c.json({ error: "not found" }, 404);
  c.executionCtx.waitUntil(bumpAllHosts(c.env, human(c), "IOC watch changed"));
  return c.json({ ok: true });
});

api.post("/iocs/import", async (c) => {
  const raw = await c.req.text();
  if (raw.length > 5_000_000) return c.json({ error: "too large" }, 413);
  const ct = c.req.header("Content-Type") ?? "";
  const name = (c.req.query("name") ?? "upload").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 60) || "upload";
  let parsed: ReturnType<typeof parseIocCsv>;
  if (ct.includes("json") || raw.trimStart().startsWith("{")) {
    try {
      parsed = parseStixBundle(JSON.parse(raw));
    } catch {
      return c.json({ error: "invalid JSON" }, 400);
    }
  } else parsed = parseIocCsv(raw);
  let imported = 0;
  const now = nowIso();
  const stmts = parsed.iocs.map((i) => c.env.DB.prepare("INSERT OR IGNORE INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES (?,?,?,?,NULL,1,?)").bind(crypto.randomUUID(), i.type, i.value, `import:${name}`, now));
  for (let i = 0; i < stmts.length; i += 50) for (const r of await c.env.DB.batch(stmts.slice(i, i + 50))) imported += r.meta.changes;
  if (imported) c.executionCtx.waitUntil(bumpAllHosts(c.env, human(c), `imported ${imported} IOCs from ${name}`));
  await audit(c.env, { actor: human(c), event: "ioc.imported", detail: { name, imported, parsed: parsed.iocs.length, errors: parsed.errors.length } });
  return c.json({ imported, skipped: parsed.iocs.length - imported, errors: parsed.errors });
});

consoleApp.route("/api", api);
