import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import { z } from "zod";
import { serverPubkeyB64, verifyAgentRequest } from "../crypto/sign";
import { setActionState, getAction, signalWorkflow } from "../lib/actions";
import { audit } from "../lib/audit";
import { publish } from "../lib/fleet";
import { hostStub } from "../lib/stubs";
import { b64dec, logError, nowIso, sha256Hex, UUID_RE } from "../lib/util";
import { rememberServerEndpoint, signedPolicy } from "../policy/service";
import { SEVERITIES, type HostRow } from "../types";

type AgentEnv = { Bindings: Env; Variables: { host: HostRow; body: Uint8Array } };
export const agent = new Hono<AgentEnv>();

const MAX_BODY = 20 * 1024 * 1024;
export const EVIDENCE_INLINE_MAX = 8 * 1024;

/** Ed25519 request auth per PROTOCOL.md section 2. */
export const agentAuth: MiddlewareHandler<AgentEnv> = async (c, next) => {
  const hostId = c.req.header("X-Aegis-Host");
  const ts = c.req.header("X-Aegis-Ts");
  const sig = c.req.header("X-Aegis-Sig");
  if (!hostId || !ts || !sig) return c.json({ error: "missing auth headers" }, 401);
  const len = Number(c.req.header("Content-Length") ?? 0);
  if (len > MAX_BODY) return c.json({ error: "body too large" }, 413);
  const host = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(hostId).first<HostRow>();
  if (!host) return c.json({ error: "unauthorized" }, 401);
  const body = c.req.method === "GET" || c.req.method === "HEAD" ? new Uint8Array() : new Uint8Array(await c.req.arrayBuffer());
  if (body.length > MAX_BODY) return c.json({ error: "body too large" }, 413);
  const fail = await verifyAgentRequest({ pubkeyB64: host.pubkey, method: c.req.method, path: new URL(c.req.url).pathname, ts, sigB64: sig, body });
  if (fail) return c.json({ error: "unauthorized", reason: fail }, 401);
  c.set("host", host);
  c.set("body", body);
  c.executionCtx.waitUntil(rememberServerEndpoint(c.env, c.req.url).catch(() => undefined));
  await next();
};

function parseBody<T extends z.ZodTypeAny>(body: Uint8Array, schema: T): { ok: true; data: z.infer<T> } | { ok: false; error: string } {
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return { ok: false, error: "invalid JSON" };
  }
  const r = schema.safeParse(json);
  return r.success ? { ok: true, data: r.data } : { ok: false, error: r.error.issues.slice(0, 5).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") };
}

// ---------------- enroll (no auth; one-time token) ----------------
const EnrollSchema = z.object({
  token: z.string().min(8).max(200),
  hostname: z.string().min(1).max(253),
  os: z.string().max(100).default(""),
  arch: z.string().max(50).default(""),
  kernel: z.string().max(200).default(""),
  agent_version: z.string().max(50).default(""),
  pubkey: z.string().min(40).max(64),
});

agent.post("/enroll", async (c) => {
  const body = new Uint8Array(await c.req.arrayBuffer());
  if (body.length > 16 * 1024) return c.json({ error: "body too large" }, 413);
  const p = parseBody(body, EnrollSchema);
  if (!p.ok) return c.json({ error: p.error }, 400);
  const e = p.data;
  let pub: Uint8Array;
  try {
    pub = b64dec(e.pubkey);
  } catch {
    return c.json({ error: "pubkey must be base64" }, 400);
  }
  if (pub.length !== 32) return c.json({ error: "pubkey must be a raw 32-byte Ed25519 key" }, 400);

  const hostId = crypto.randomUUID();
  const now = nowIso();
  const hash = await sha256Hex(e.token);
  // Atomic one-time claim.
  const claim = await c.env.DB.prepare("UPDATE enroll_tokens SET used_at=?, host_id=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?").bind(now, hostId, hash, now).run();
  if (!claim.meta.changes) return c.json({ error: "invalid, used or expired token" }, 401);

  await c.env.DB.batch([
    c.env.DB.prepare("INSERT INTO hosts(id, hostname, os, arch, kernel, agent_version, pubkey, policy_version, status, enrolled_at, last_seen) VALUES (?,?,?,?,?,?,?,1,'ok',?,?)")
      .bind(hostId, e.hostname, e.os, e.arch, e.kernel, e.agent_version, e.pubkey, now, now),
    c.env.DB.prepare("INSERT INTO policies(host_id, version, body_json, created_by, reason, created_at) VALUES (?,1,'{}','system','enrollment',?)").bind(hostId, now),
  ]);
  c.executionCtx.waitUntil(rememberServerEndpoint(c.env, c.req.url).catch(() => undefined));
  const host = (await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(hostId).first<HostRow>())!;
  await audit(c.env, { actor: "system", event: "host.enrolled", host_id: hostId, detail: { hostname: e.hostname, os: e.os, arch: e.arch } });
  await publish(c.env, "host", host as unknown as Record<string, unknown>);
  return c.json({ host_id: hostId, server_pubkey: await serverPubkeyB64(c.env.SIGNING_KEY_JWK), policy: await signedPolicy(c.env, host) });
});

agent.use("*", async (c, next) => (c.req.path === "/v1/enroll" ? next() : agentAuth(c, next)));

// ---------------- events ----------------
const AnomalySchema = z.object({
  id: z.string().regex(UUID_RE),
  ts: z.string(),
  rule_id: z.string().min(1).max(200),
  rule_source: z.enum(["sigma", "native", "baseline", "ioc", "yara"]),
  rule_title: z.string().max(500).default(""),
  category: z.enum(["auth", "process", "network", "file", "user", "persistence", "other"]),
  severity: z.enum(SEVERITIES as unknown as [string, ...string[]]),
  fingerprint: z.string().min(1).max(200),
  summary: z.string().max(2000),
  attack_tags: z.array(z.string().max(100)).max(50).default([]),
  falsepositives: z.array(z.string().max(300)).max(20).default([]),
  shadow: z.boolean().default(false),
  evidence: z.record(z.string(), z.unknown()).default({}),
});
const EventsSchema = z.object({ anomalies: z.array(z.unknown()).max(500) });

agent.post("/events", async (c) => {
  const host = c.get("host");
  const p = parseBody(c.get("body"), EventsSchema);
  if (!p.ok) return c.json({ error: p.error }, 400);
  const now = nowIso();
  const stmts: D1PreparedStatement[] = [];
  const meta: { id: string; shadow: boolean; rule_id: string; row: Record<string, unknown> }[] = [];
  let rejected = 0;
  for (const raw of p.data.anomalies) {
    const r = AnomalySchema.safeParse(raw);
    if (!r.success) {
      rejected++;
      continue;
    }
    const a = r.data;
    const t = Date.parse(a.ts);
    const ts = Number.isFinite(t) ? new Date(t).toISOString() : now;
    const evJson = JSON.stringify(a.evidence);
    let evInline: string | null = null;
    let evKey: string | null = null;
    if (new TextEncoder().encode(evJson).length > EVIDENCE_INLINE_MAX) {
      if (!a.shadow) {
        evKey = `evidence/${host.id}/${a.id}.json`;
        await c.env.EVIDENCE.put(evKey, evJson, { httpMetadata: { contentType: "application/json" } });
      }
    } else evInline = evJson;
    stmts.push(
      c.env.DB.prepare(
        `INSERT OR IGNORE INTO anomalies(id, host_id, incident_id, ts, rule_id, rule_source, rule_title, category, severity, fingerprint, summary, attack_tags_json, falsepositives_json, shadow, evidence_json, evidence_r2_key, received_at)
         VALUES (?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      ).bind(a.id, host.id, ts, a.rule_id, a.rule_source, a.rule_title, a.category, a.severity, a.fingerprint, a.summary, JSON.stringify(a.attack_tags), JSON.stringify(a.falsepositives), a.shadow ? 1 : 0, evInline, evKey, now),
    );
    meta.push({ id: a.id, shadow: a.shadow, rule_id: a.rule_id, row: { id: a.id, host_id: host.id, incident_id: null, ts, rule_id: a.rule_id, rule_source: a.rule_source, rule_title: a.rule_title, category: a.category, severity: a.severity, fingerprint: a.fingerprint, summary: a.summary, attack_tags_json: JSON.stringify(a.attack_tags), falsepositives_json: JSON.stringify(a.falsepositives), shadow: a.shadow ? 1 : 0, evidence_json: evInline, evidence_r2_key: evKey, received_at: now } });
  }
  const inserted: typeof meta = [];
  for (let i = 0; i < stmts.length; i += 50) {
    const res = await c.env.DB.batch(stmts.slice(i, i + 50));
    res.forEach((r, j) => {
      if (r.meta.changes > 0) inserted.push(meta[i + j]!);
    });
  }
  // rule hit counters (shadow and active both)
  const hits = new Map<string, number>();
  for (const m of inserted) hits.set(m.rule_id, (hits.get(m.rule_id) ?? 0) + 1);
  const hitStmts = [...hits].map(([rid, n]) => c.env.DB.prepare("UPDATE rules SET hits_total=hits_total+? WHERE id=?").bind(n, rid));
  for (let i = 0; i < hitStmts.length; i += 50) await c.env.DB.batch(hitStmts.slice(i, i + 50));

  const toTriage = inserted.filter((m) => !m.shadow);
  for (let i = 0; i < toTriage.length; i += 100) await c.env.TRIAGE.sendBatch(toTriage.slice(i, i + 100).map((m) => ({ body: { anomaly_id: m.id } })));
  c.executionCtx.waitUntil(
    (async () => {
      for (const m of toTriage.slice(0, 50)) await publish(c.env, "anomaly", m.row);
    })(),
  );
  await c.env.DB.prepare("UPDATE hosts SET last_seen=? WHERE id=?").bind(now, host.id).run();
  return c.json({ accepted: inserted.length + (meta.length - inserted.length), rejected });
});

// ---------------- heartbeat ----------------
const HeartbeatSchema = z.object({
  agent_version: z.string().max(50).default(""),
  policy_version: z.number().int().nonnegative().default(0),
  uptime_s: z.number().nonnegative().default(0),
  stats: z.record(z.string(), z.unknown()).default({}),
  rule_errors: z.array(z.object({ rule_id: z.string().max(200), error: z.string().max(1000) })).max(500).default([]),
  ws_connected: z.boolean().default(false),
});

agent.post("/heartbeat", async (c) => {
  const host = c.get("host");
  const p = parseBody(c.get("body"), HeartbeatSchema);
  if (!p.ok) return c.json({ error: p.error }, 400);
  const hb = p.data;
  const status = host.status === "isolated" ? "isolated" : hb.rule_errors.length > 0 ? "degraded" : "ok";
  const now = nowIso();
  await c.env.DB.prepare("UPDATE hosts SET last_seen=?, agent_version=COALESCE(NULLIF(?, ''), agent_version), status=?, stats_json=?, rule_errors_json=? WHERE id=?")
    .bind(now, hb.agent_version, status, JSON.stringify({ ...hb.stats, uptime_s: hb.uptime_s, ws_connected: hb.ws_connected, agent_policy_version: hb.policy_version }), JSON.stringify(hb.rule_errors), host.id).run();
  const row = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(host.id).first<Record<string, unknown>>();
  if (row) c.executionCtx.waitUntil(publish(c.env, "host", row));
  return c.json({ policy_version: host.policy_version });
});

agent.get("/policy", async (c) => {
  const host = (await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(c.get("host").id).first<HostRow>())!;
  return c.json(await signedPolicy(c.env, host));
});

agent.get("/commands", async (c) => {
  try {
    return c.json({ commands: await hostStub(c.env, c.get("host").id).pendingCommands() });
  } catch (e) {
    logError("pendingCommands failed", e);
    return c.json({ commands: [] });
  }
});

// ---------------- results ----------------
const ResultSchema = z.object({
  command_id: z.string().min(1).max(100),
  status: z.enum(["succeeded", "failed", "rejected"]),
  result: z.record(z.string(), z.unknown()).optional(),
  error: z.string().max(4000).optional(),
  rollback_token: z.string().max(512).optional(),
});

agent.post("/results", async (c) => {
  const host = c.get("host");
  const p = parseBody(c.get("body"), ResultSchema);
  if (!p.ok) return c.json({ error: p.error }, 400);
  const r = p.data;
  const action = await getAction(c.env, r.command_id);
  if (!action || action.host_id !== host.id) return c.json({ error: "unknown command" }, 404);
  const stub = hostStub(c.env, host.id);
  if (!["dispatched", "expired", "approved"].includes(action.state)) {
    await stub.ack(r.command_id).catch(() => undefined);
    return c.json({ ok: true }); // duplicate delivery
  }
  let result: unknown = r.result ?? {};
  const resStr = JSON.stringify(result);
  if (resStr.length > 100_000) {
    const key = `evidence/${host.id}/${action.id}.result.json`;
    await c.env.EVIDENCE.put(key, resStr, { httpMetadata: { contentType: "application/json" } });
    result = { r2_key: key, truncated: true, preview: resStr.slice(0, 2000) };
  }
  const state = r.status === "succeeded" ? "succeeded" : "failed";
  const error = r.status === "rejected" ? `agent rejected: ${r.error ?? "no reason"}` : (r.error ?? null);
  const row = await setActionState(c.env, action.id, state, { result, error, rollback_token: r.rollback_token ?? null });
  await stub.ack(r.command_id).catch(() => undefined);
  await audit(c.env, { actor: `agent:${host.hostname}`, event: `action.${state}`, incident_id: action.incident_id, host_id: host.id, action_id: action.id, detail: { action: action.action, error } });

  if (state === "succeeded") {
    const newStatus = action.action === "isolate_host" ? "isolated" : null;
    if (newStatus) await c.env.DB.prepare("UPDATE hosts SET status=? WHERE id=?").bind(newStatus, host.id).run();
    if (action.action === "rollback" && action.rollback_of) {
      await setActionState(c.env, action.rollback_of, "rolled_back");
      const orig = await getAction(c.env, action.rollback_of);
      if (orig?.action === "isolate_host") await c.env.DB.prepare("UPDATE hosts SET status='ok' WHERE id=? AND status='isolated'").bind(host.id).run();
      await audit(c.env, { actor: `agent:${host.hostname}`, event: "action.rolled_back", incident_id: action.incident_id, host_id: host.id, action_id: action.rollback_of });
    }
    const h = await c.env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(host.id).first<Record<string, unknown>>();
    if (h) await publish(c.env, "host", h);
  }
  c.executionCtx.waitUntil(signalWorkflow(c.env, action.incident_id, "evidence", { action_id: row.id, status: row.state }));
  return c.json({ ok: true });
});

// ---------------- websocket ----------------
agent.get("/ws", async (c) => {
  if (c.req.header("Upgrade")?.toLowerCase() !== "websocket") return c.json({ error: "websocket upgrade required" }, 426);
  const host = c.get("host");
  await c.env.DB.prepare("UPDATE hosts SET last_seen=? WHERE id=?").bind(nowIso(), host.id).run();
  return hostStub(c.env, host.id).fetch(c.req.raw);
});

