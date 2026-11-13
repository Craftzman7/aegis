import { audit } from "./lib/audit";
import { publish } from "./lib/fleet";
import { setActionState } from "./lib/actions";
import { errMsg, logError, nowIso } from "./lib/util";
import { isNonPublicIp } from "./policy/gate";
import { bumpAllHosts } from "./policy/service";
import { syncSigmaHQ } from "./sigma/sync";
import { SEV_RANK, type ActionRow, type Severity } from "./types";

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const SHA_RE = /\b[a-f0-9]{64}\b/gi;
const H = 3600_000;

export async function handleScheduled(controller: ScheduledController, env: Env): Promise<void> {
  const jobs: [string, () => Promise<unknown>][] =
    controller.cron === "0 6 * * *"
      ? [["digest", () => dailyDigest(env)], ["sigma_sync", () => syncSigmaHQ(env)], ["hourly", () => hourly(env)]]
      : [["hourly", () => hourly(env)]];
  for (const [name, fn] of jobs) {
    try {
      await fn();
    } catch (e) {
      logError(`cron job ${name} failed`, e);
      await audit(env, { actor: "system", event: "cron.failed", detail: { job: name, error: errMsg(e) } });
    }
  }
}

async function hourly(env: Env): Promise<void> {
  await expireStale(env);
  await fleetCorrelation(env);
  await promoteShadowRules(env);
}

/** Expire proposals past expires_at; fail dispatched commands with no result for >1h. */
export async function expireStale(env: Env): Promise<{ expired: number; failed: number }> {
  const now = nowIso();
  const proposals = (await env.DB.prepare("SELECT * FROM actions WHERE state='proposed' AND expires_at IS NOT NULL AND expires_at<?").bind(now).all<ActionRow>()).results;
  for (const a of proposals) {
    await setActionState(env, a.id, "expired", { error: "approval window elapsed" });
    await audit(env, { actor: "system", event: "action.expired", incident_id: a.incident_id, host_id: a.host_id, action_id: a.id });
    if (a.incident_id) await env.DB.prepare("UPDATE incidents SET status='open', updated_at=? WHERE id=? AND status='awaiting_approval' AND NOT EXISTS (SELECT 1 FROM actions WHERE incident_id=? AND state='proposed')").bind(now, a.incident_id, a.incident_id).run();
  }
  const cutoff = new Date(Date.now() - H).toISOString();
  const stale = (await env.DB.prepare("SELECT * FROM actions WHERE state='dispatched' AND updated_at<?").bind(cutoff).all<ActionRow>()).results;
  for (const a of stale) await setActionState(env, a.id, "failed", { error: "no result from agent" });
  return { expired: proposals.length, failed: stale.length };
}

/** Same IOC/sha256/IP/rule fingerprint on >=2 hosts in 24h => escalate or open a fleet incident. */
export async function fleetCorrelation(env: Env): Promise<number> {
  const since = new Date(Date.now() - 24 * H).toISOString();
  const rows = (await env.DB.prepare("SELECT id, host_id, incident_id, fingerprint, evidence_json, rule_id FROM anomalies WHERE ts>=? AND shadow=0 LIMIT 5000").bind(since).all<{ id: string; host_id: string; incident_id: string | null; fingerprint: string; evidence_json: string | null; rule_id: string }>()).results;
  const groups = new Map<string, { kind: string; value: string; hosts: Set<string>; incidents: Set<string> }>();
  const add = (kind: string, value: string, r: { host_id: string; incident_id: string | null }) => {
    const k = `${kind}:${value}`;
    let g = groups.get(k);
    if (!g) groups.set(k, (g = { kind, value, hosts: new Set(), incidents: new Set() }));
    g.hosts.add(r.host_id);
    if (r.incident_id) g.incidents.add(r.incident_id);
  };
  for (const r of rows) {
    add("fingerprint", r.fingerprint, r);
    if (r.evidence_json) {
      for (const ip of new Set(r.evidence_json.match(IP_RE) ?? [])) if (!isNonPublicIp(ip)) add("ip", ip, r);
      for (const h of new Set((r.evidence_json.match(SHA_RE) ?? []).map((x) => x.toLowerCase()))) add("sha256", h, r);
    }
  }
  let n = 0;
  for (const g of groups.values()) {
    if (g.hosts.size < 2) continue;
    const key = `${g.kind}:${g.value}`;
    const dup = await env.DB.prepare("SELECT 1 AS x FROM audit_log WHERE event='fleet.correlation' AND ts>=? AND detail_json LIKE ? LIMIT 1").bind(since, `%"key":${JSON.stringify(key)}%`).first();
    if (dup) continue;
    n++;
    const newSev: Severity = g.hosts.size >= 3 ? "critical" : "high";
    const hostList = [...g.hosts];
    let escalated = 0;
    for (const iid of g.incidents) {
      const inc = await env.DB.prepare("SELECT severity FROM incidents WHERE id=? AND status NOT LIKE 'closed%'").bind(iid).first<{ severity: Severity }>();
      if (inc && SEV_RANK[inc.severity] < SEV_RANK[newSev]) {
        await env.DB.prepare("UPDATE incidents SET severity=?, updated_at=? WHERE id=?").bind(newSev, nowIso(), iid).run();
        escalated++;
        const row = await env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(iid).first<Record<string, unknown>>();
        if (row) await publish(env, "incident", row);
      }
    }
    let fleetIncident: string | null = null;
    if (g.incidents.size === 0) {
      fleetIncident = crypto.randomUUID();
      const now = nowIso();
      await env.DB.prepare("INSERT INTO incidents(id, host_id, title, status, severity, ai_summary, created_at, updated_at) VALUES (?,?,?,'open',?,?,?,?)")
        .bind(fleetIncident, hostList[0]!, `Fleet correlation: ${g.kind} ${g.value.slice(0, 80)} on ${g.hosts.size} hosts`, newSev, `Seen on hosts: ${hostList.join(", ")}`, now, now).run();
      const row = await env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(fleetIncident).first<Record<string, unknown>>();
      if (row) await publish(env, "incident", row);
    }
    if (g.kind !== "fingerprint") {
      await env.DB.prepare("INSERT OR IGNORE INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES (?,?,?,?,?,0,?)")
        .bind(crypto.randomUUID(), g.kind, g.value, "incident", fleetIncident ?? [...g.incidents][0] ?? null, nowIso()).run();
    }
    await audit(env, { actor: "system", event: "fleet.correlation", incident_id: fleetIncident ?? [...g.incidents][0] ?? null, detail: { key, hosts: hostList, escalated, fleet_incident: fleetIncident } });
  }
  return n;
}

/** Promote shadow rules after >=72h shadow, >=5 hits, 0 FP labels. */
export async function promoteShadowRules(env: Env): Promise<string[]> {
  const cutoff = new Date(Date.now() - 72 * H).toISOString();
  const rules = (await env.DB.prepare("SELECT id, title FROM rules WHERE status='shadow' AND shadow_since IS NOT NULL AND shadow_since<=? AND hits_total>=5 AND fp_total=0").bind(cutoff).all<{ id: string; title: string }>()).results;
  if (!rules.length) return [];
  const now = nowIso();
  for (const r of rules) {
    await env.DB.prepare("UPDATE rules SET status='active', shadow_since=NULL, updated_at=? WHERE id=?").bind(now, r.id).run();
    await audit(env, { actor: "ai", event: "rule.promoted", detail: { rule_id: r.id, title: r.title, reason: "72h shadow, >=5 hits, 0 FP labels" } });
  }
  await bumpAllHosts(env, "ai", `auto-promoted ${rules.length} shadow rule(s)`);
  return rules.map((r) => r.id);
}

export async function dailyDigest(env: Env, day = new Date()): Promise<string> {
  const since = new Date(day.getTime() - 24 * H).toISOString();
  const q = async <T extends Record<string, unknown>>(sql: string, ...b: unknown[]) => (await env.DB.prepare(sql).bind(...b).all<T>()).results;
  const digest = {
    generated_at: nowIso(),
    window_start: since,
    incidents_by_severity: await q("SELECT severity, COUNT(*) AS n FROM incidents WHERE created_at>=? GROUP BY severity", since),
    incidents_by_status: await q("SELECT status, COUNT(*) AS n FROM incidents WHERE created_at>=? GROUP BY status", since),
    anomalies: (await q<{ n: number }>("SELECT COUNT(*) AS n FROM anomalies WHERE received_at>=? AND shadow=0", since))[0]?.n ?? 0,
    top_rules: await q("SELECT rule_id, COUNT(*) AS n FROM anomalies WHERE received_at>=? GROUP BY rule_id ORDER BY n DESC LIMIT 10", since),
    actions_by_state: await q("SELECT state, proposed_by LIKE 'human%' AS human, COUNT(*) AS n FROM actions WHERE created_at>=? GROUP BY state, human", since),
    pending_approvals: (await q<{ n: number }>("SELECT COUNT(*) AS n FROM actions WHERE state='proposed'"))[0]?.n ?? 0,
    false_positive_incidents: await q("SELECT id, title FROM incidents WHERE verdict='false_positive' AND updated_at>=? LIMIT 20", since),
    silent_hosts: await q("SELECT id, hostname, last_seen FROM hosts WHERE last_seen IS NULL OR last_seen<?", new Date(Date.now() - 6 * H).toISOString()),
    shadow_rules_near_promotion: await q("SELECT id, title, hits_total, fp_total FROM rules WHERE status='shadow' AND hits_total>=3 ORDER BY hits_total DESC LIMIT 10"),
    suppression_drift: await q("SELECT COUNT(*) AS n FROM audit_log WHERE event='policy.updated' AND actor='ai' AND ts>=? AND detail_json LIKE '%suppress%'", since),
  };
  const key = `digests/${day.toISOString().slice(0, 10)}.json`;
  await env.EVIDENCE.put(key, JSON.stringify(digest, null, 2), { httpMetadata: { contentType: "application/json" } });
  await audit(env, { actor: "system", event: "digest.created", detail: { key, incidents: digest.incidents_by_status } });
  return key;
}

