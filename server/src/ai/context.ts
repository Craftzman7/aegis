import { effectiveThresholds } from "../policy/service";
import { safeJson, placeholders } from "../lib/util";
import type { ActionRow, AnomalyRow, HostRow, IncidentRow } from "../types";
import type { AnalysisContext } from "./analyst";
import { findSimilar } from "./memory";

export async function loadEvidence(env: Env, a: AnomalyRow): Promise<unknown> {
  if (a.evidence_json) return safeJson(a.evidence_json, a.evidence_json);
  if (a.evidence_r2_key) {
    try {
      const o = await env.EVIDENCE.get(a.evidence_r2_key);
      if (o) return safeJson(await o.text(), null);
    } catch {
      /* fall through */
    }
  }
  return null;
}

export async function loadContext(env: Env, incidentId: string, step: AnalysisContext["step"], round: number): Promise<AnalysisContext> {
  const incident = await env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(incidentId).first<IncidentRow>();
  if (!incident) throw new Error(`incident ${incidentId} not found`);
  const host = (await env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(incident.host_id).first<HostRow>())!;
  const anomalies = (await env.DB.prepare("SELECT * FROM anomalies WHERE incident_id=? ORDER BY ts LIMIT 50").bind(incidentId).all<AnomalyRow>()).results;
  const evidence = await Promise.all(anomalies.slice(0, 25).map(async (a) => ({ anomaly_id: a.id, evidence: await loadEvidence(env, a) })));
  const actions = (await env.DB.prepare("SELECT * FROM actions WHERE incident_id=? ORDER BY created_at").bind(incidentId).all<ActionRow>()).results;
  const reviews = (
    await env.DB.prepare("SELECT output_json, step, round FROM ai_reviews WHERE incident_id=? AND step!='ask' ORDER BY ts").bind(incidentId).all<{ output_json: string; step: string; round: number }>()
  ).results;
  const priorReviews = reviews.map((r) => {
    const o = safeJson<{ verdict?: string; severity?: string; confidence?: number; rationale?: string }>(r.output_json, {});
    return { step: r.step, round: r.round, verdict: o.verdict ?? "?", severity: o.severity ?? "?", confidence: o.confidence ?? 0, rationale: o.rationale ?? "" };
  });
  const recent = (
    await env.DB.prepare("SELECT id, title, severity, verdict, status FROM incidents WHERE host_id=? AND id!=? ORDER BY created_at DESC LIMIT 5").bind(incident.host_id, incidentId).all<{ id: string; title: string; severity: string; verdict: string | null; status: string }>()
  ).results;
  const ruleIds = [...new Set(anomalies.map((a) => a.rule_id))].slice(0, 20);
  let feedback: AnalysisContext["feedback"] = [];
  if (ruleIds.length) {
    const rows = (
      await env.DB.prepare(
        `SELECT DISTINCT i.id, i.title, i.verdict, i.analyst_note FROM incidents i JOIN anomalies a ON a.incident_id=i.id
         WHERE a.rule_id IN (${placeholders(ruleIds.length)}) AND i.verdict IN ('true_positive','false_positive') AND i.id!=? ORDER BY i.updated_at DESC LIMIT 6`,
      ).bind(...ruleIds, incidentId).all<{ id: string; title: string; verdict: string; analyst_note: string | null }>()
    ).results;
    feedback = rows.map((r) => ({ incident_id: r.id, title: r.title, label: r.verdict, note: r.analyst_note, rule_ids: ruleIds }));
  }
  const queryText = `${incident.title}\n${anomalies.slice(0, 5).map((a) => a.summary).join("\n")}`;
  const similar = await findSimilar(env, queryText, incidentId);
  const thresholds = await effectiveThresholds(env, incident.host_id);
  return { round, step, incident, host, anomalies, evidence, actions, priorReviews, recentHostIncidents: recent, similar, feedback, thresholds };
}
