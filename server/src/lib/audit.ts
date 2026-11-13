import { publish } from "./fleet";
import { logError, nowIso } from "./util";

export interface AuditInput {
  actor: string;
  event: string;
  incident_id?: string | null;
  host_id?: string | null;
  action_id?: string | null;
  detail?: unknown;
}

export async function audit(env: Env, a: AuditInput): Promise<void> {
  try {
    const row = await env.DB.prepare(
      "INSERT INTO audit_log(ts, actor, event, incident_id, host_id, action_id, detail_json) VALUES (?,?,?,?,?,?,?) RETURNING *",
    )
      .bind(nowIso(), a.actor, a.event, a.incident_id ?? null, a.host_id ?? null, a.action_id ?? null, a.detail === undefined ? null : JSON.stringify(a.detail))
      .first<Record<string, unknown>>();
    if (row) await publish(env, "audit", row);
  } catch (e) {
    logError("audit write failed", e, { event: a.event });
  }
}
