import { getAutonomy } from "./lib/actions";
import { audit } from "./lib/audit";
import { publish } from "./lib/fleet";
import { errMsg, logError, nowIso, safeJson } from "./lib/util";
import { SEV_RANK, type AnomalyRow, type IncidentRow, type Severity } from "./types";

export const CORRELATION_WINDOW_MS = 30 * 60 * 1000;

export interface TriageMessage {
  anomaly_id: string;
}

/** Attach the anomaly to an open incident for the same host within the window, or create one. */
export async function correlateAnomaly(env: Env, anomaly: AnomalyRow): Promise<{ incident: IncidentRow; created: boolean }> {
  const since = new Date(Date.now() - CORRELATION_WINDOW_MS).toISOString();
  const existing = await env.DB.prepare(
    "SELECT * FROM incidents WHERE host_id=? AND status IN ('open','investigating','awaiting_approval') AND updated_at>=? ORDER BY updated_at DESC LIMIT 1",
  ).bind(anomaly.host_id, since).first<IncidentRow>();
  const now = nowIso();
  const tags = safeJson<string[]>(anomaly.attack_tags_json, []);
  if (existing) {
    const sev: Severity = SEV_RANK[anomaly.severity] > SEV_RANK[existing.severity] ? anomaly.severity : existing.severity;
    const merged = [...new Set([...safeJson<string[]>(existing.attack_tags_json, []), ...tags])].slice(0, 40);
    await env.DB.batch([
      env.DB.prepare("UPDATE anomalies SET incident_id=? WHERE id=?").bind(existing.id, anomaly.id),
      env.DB.prepare("UPDATE incidents SET severity=?, attack_tags_json=?, updated_at=? WHERE id=?").bind(sev, JSON.stringify(merged), now, existing.id),
    ]);
    return { incident: { ...existing, severity: sev, updated_at: now }, created: false };
  }
  const id = crypto.randomUUID();
  const title = (anomaly.rule_title || anomaly.summary || anomaly.rule_id).slice(0, 200);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO incidents(id, host_id, title, status, severity, attack_tags_json, created_at, updated_at) VALUES (?,?,?,'open',?,?,?,?)")
      .bind(id, anomaly.host_id, title, anomaly.severity, JSON.stringify(tags), now, now),
    env.DB.prepare("UPDATE anomalies SET incident_id=? WHERE id=?").bind(id, anomaly.id),
  ]);
  const inc = (await env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(id).first<IncidentRow>())!;
  await audit(env, { actor: "system", event: "incident.created", incident_id: id, host_id: anomaly.host_id, detail: { title, anomaly_id: anomaly.id } });
  return { incident: inc, created: true };
}

/** Start the investigation workflow for an incident that has none (used when autonomy is un-paused). */
export async function startOrResumeWorkflow(env: Env, inc: IncidentRow): Promise<void> {
  await startOrSignal(env, inc, true, "");
}

async function startOrSignal(env: Env, inc: IncidentRow, created: boolean, anomalyId: string): Promise<void> {
  if (created || !inc.workflow_id) {
    await env.INVESTIGATION.create({ id: inc.id, params: { incident_id: inc.id } });
    await env.DB.prepare("UPDATE incidents SET workflow_id=? WHERE id=?").bind(inc.id, inc.id).run();
    return;
  }
  try {
    const inst = await env.INVESTIGATION.get(inc.workflow_id);
    const st = await inst.status();
    if (st.status === "complete" || st.status === "errored" || st.status === "terminated") {
      const wid = `${inc.id}-r${Date.now()}`;
      await env.INVESTIGATION.create({ id: wid, params: { incident_id: inc.id } });
      await env.DB.prepare("UPDATE incidents SET workflow_id=? WHERE id=?").bind(wid, inc.id).run();
    } else {
      await inst.sendEvent({ type: "new_anomaly", payload: { anomaly_id: anomalyId } });
    }
  } catch (e) {
    // Instance missing: start a fresh one. Otherwise the event is only a hint (workflow re-reads D1).
    if (/not.?found|does not exist|invalid/i.test(errMsg(e))) {
      await env.INVESTIGATION.create({ id: `${inc.id}-r${Date.now()}`, params: { incident_id: inc.id } });
    } else logError("sendEvent(new_anomaly) failed", e, { incident_id: inc.id });
  }
}

export async function handleTriageMessage(env: Env, msg: TriageMessage): Promise<void> {
  const a = await env.DB.prepare("SELECT * FROM anomalies WHERE id=?").bind(msg.anomaly_id).first<AnomalyRow>();
  if (!a || a.shadow) return;
  if (a.incident_id) return; // already correlated (queue redelivery)
  const { incident, created } = await correlateAnomaly(env, a);
  await publish(env, "incident", incident as unknown as Record<string, unknown>);
  if ((await getAutonomy(env, a.host_id)) === "paused") {
    await audit(env, { actor: "system", event: "triage.paused", incident_id: incident.id, host_id: a.host_id, detail: { anomaly_id: a.id } });
    return; // incident stays open; no workflow
  }
  await startOrSignal(env, incident, created, a.id);
}

export async function handleQueue(batch: MessageBatch<TriageMessage>, env: Env): Promise<void> {
  for (const m of batch.messages) {
    try {
      await handleTriageMessage(env, m.body);
      m.ack();
    } catch (e) {
      logError("triage message failed", e, { anomaly_id: m.body?.anomaly_id, attempts: m.attempts });
      m.retry({ delaySeconds: Math.min(300, 5 * 2 ** m.attempts) });
    }
  }
}
