import type { AnalystOutput } from "../ai/analyst";
import { audit } from "./audit";
import { publish } from "./fleet";
import { getIncident, publishIncident } from "./incidents";
import { nowIso, safeJson } from "./util";

/** Persist an AI review (idempotent by id) and fold its verdict/severity/tags/IOCs into the incident. Shared by the rounds and loop paths. */
export async function recordReview(
  env: Env,
  incidentId: string,
  r: { reviewId: string; step: string; round: number; model: string; promptHash: string; output: AnalystOutput; auditExtra?: Record<string, unknown> },
): Promise<void> {
  const inc = await getIncident(env, incidentId);
  if (!inc) return;
  const o = r.output;
  const ts = nowIso();
  await env.DB.prepare("INSERT OR IGNORE INTO ai_reviews(id, incident_id, step, round, model, prompt_hash, output_json, gate_json, ts) VALUES (?,?,?,?,?,?,?,NULL,?)")
    .bind(r.reviewId, incidentId, r.step, r.round, r.model, r.promptHash, JSON.stringify(o), ts).run();
  const tags = [...new Set([...safeJson<string[]>(inc.attack_tags_json, []), ...o.attack_tags])].slice(0, 40);
  await env.DB.prepare(
    "UPDATE incidents SET verdict=?, severity=?, confidence=?, attack_tags_json=?, status=CASE WHEN status='open' THEN 'investigating' ELSE status END, updated_at=? WHERE id=? AND status NOT LIKE 'closed%'",
  ).bind(o.verdict, o.severity, o.confidence, JSON.stringify(tags), ts, incidentId).run();
  for (const ioc of o.iocs.slice(0, 30)) {
    // AI-extracted IOCs are NOT pushed to agents (watch=0) until a human confirms the incident.
    await env.DB.prepare("INSERT OR IGNORE INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES (?,?,?,?,?,0,?)")
      .bind(crypto.randomUUID(), ioc.type, ioc.type === "sha256" ? ioc.value.toLowerCase() : ioc.value, "ai", incidentId, ts).run();
  }
  await audit(env, { actor: "ai", event: `ai.${r.step}`, incident_id: incidentId, host_id: inc.host_id, detail: { review_id: r.reviewId, verdict: o.verdict, severity: o.severity, confidence: o.confidence, requests: o.requests.length, ...r.auditExtra } });
  const row = await env.DB.prepare("SELECT * FROM ai_reviews WHERE id=?").bind(r.reviewId).first<Record<string, unknown>>();
  if (row) await publish(env, "ai_review", row);
  await publishIncident(env, incidentId);
}
