import { signEnvelope } from "../crypto/sign";
import { applyPolicyAction } from "../policy/service";
import type { ActionRow, AutonomyMode, Command } from "../types";
import { audit } from "./audit";
import { publish } from "./fleet";
import { hostStub } from "./stubs";
import { errMsg, logError, nowIso, safeJson } from "./util";

export const COMMAND_TTL_S = 900; // unapproved-in-time commands expire after 15 min
export const PROPOSAL_TTL_S = 24 * 3600;

export async function getAutonomy(env: Env, hostId: string): Promise<AutonomyMode> {
  const h = await env.DB.prepare("SELECT autonomy FROM hosts WHERE id=?").bind(hostId).first<{ autonomy: AutonomyMode | null }>();
  if (h?.autonomy) return h.autonomy;
  const g = await env.DB.prepare("SELECT value FROM settings WHERE key='autonomy'").first<{ value: string }>();
  const v = g?.value;
  return v === "propose_only" || v === "paused" ? v : "autonomous";
}

export interface NewAction {
  id: string;
  incident_id: string | null;
  host_id: string;
  action: string;
  params: Record<string, unknown>;
  tier: number;
  kind: "command" | "policy";
  state: "proposed" | "approved" | "rejected";
  proposed_by: string;
  rationale?: string | null;
  approved_by?: string | null;
  reject_reason?: string | null;
  rollback_of?: string | null;
  expires_at?: string | null;
  critic?: unknown;
}

/** Idempotent insert (same id => no-op). Returns the stored row. */
export async function createAction(env: Env, a: NewAction): Promise<ActionRow> {
  const now = nowIso();
  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO actions(id, incident_id, host_id, action, params_json, tier, kind, state, proposed_by, rationale, approved_by, reject_reason, rollback_of, expires_at, critic_json, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  )
    .bind(a.id, a.incident_id, a.host_id, a.action, JSON.stringify(a.params), a.tier, a.kind, a.state, a.proposed_by, a.rationale ?? null, a.approved_by ?? null, a.reject_reason ?? null, a.rollback_of ?? null, a.expires_at ?? null, a.critic === undefined ? null : JSON.stringify(a.critic), now, now)
    .run();
  const row = (await getAction(env, a.id))!;
  if (res.meta.changes) {
    await audit(env, {
      actor: a.proposed_by,
      event: a.state === "proposed" ? "action.proposed" : a.state === "rejected" ? "action.gate_rejected" : "action.created",
      incident_id: a.incident_id,
      host_id: a.host_id,
      action_id: a.id,
      detail: { action: a.action, tier: a.tier, params: a.params, reason: a.reject_reason ?? a.rationale },
    });
    await publish(env, "action", row as unknown as Record<string, unknown>);
  }
  return row;
}

export const getAction = (env: Env, id: string) => env.DB.prepare("SELECT * FROM actions WHERE id=?").bind(id).first<ActionRow>();

export async function setActionState(env: Env, id: string, state: string, extra: { error?: string | null; result?: unknown; approved_by?: string; rollback_token?: string | null; reject_reason?: string | null } = {}): Promise<ActionRow> {
  await env.DB.prepare(
    `UPDATE actions SET state=?, updated_at=?, error=COALESCE(?, error), result_json=COALESCE(?, result_json), approved_by=COALESCE(?, approved_by),
       rollback_token=COALESCE(?, rollback_token), reject_reason=COALESCE(?, reject_reason) WHERE id=?`,
  )
    .bind(state, nowIso(), extra.error ?? null, extra.result === undefined ? null : JSON.stringify(extra.result), extra.approved_by ?? null, extra.rollback_token ?? null, extra.reject_reason ?? null, id)
    .run();
  const row = (await getAction(env, id))!;
  await publish(env, "action", row as unknown as Record<string, unknown>);
  return row;
}

/**
 * Execute an approved action: policy actions are applied server-side (new signed policy version);
 * commands are signed and handed to the HostDO. Safe to call twice: only acts on state=approved.
 */
export async function dispatchAction(env: Env, action: ActionRow, actor: string, opts: { ttlSeconds?: number } = {}): Promise<ActionRow> {
  if (action.state !== "approved") return action;
  const params = safeJson<Record<string, unknown>>(action.params_json, {});
  if (opts.ttlSeconds !== undefined && "ttl_seconds" in params) params.ttl_seconds = opts.ttlSeconds;
  if (action.kind === "policy") {
    try {
      const result = await applyPolicyAction(env, action.host_id, action.action, params, action.proposed_by.startsWith("human") ? action.proposed_by : "ai", action.rationale ?? action.action);
      await audit(env, { actor, event: "action.applied", incident_id: action.incident_id, host_id: action.host_id, action_id: action.id, detail: { action: action.action, result } });
      return await setActionState(env, action.id, "succeeded", { result });
    } catch (e) {
      logError("policy action failed", e, { action_id: action.id });
      await audit(env, { actor, event: "action.failed", incident_id: action.incident_id, host_id: action.host_id, action_id: action.id, detail: { error: errMsg(e) } });
      return await setActionState(env, action.id, "failed", { error: errMsg(e) });
    }
  }
  const now = Date.now();
  const ttl = action.tier >= 1 ? 3600 : COMMAND_TTL_S; // approved tier-1 may have waited; give agent an hour
  const cmd: Command = {
    id: action.id,
    host_id: action.host_id,
    action: action.action as Command["action"],
    params,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString(),
  };
  const envelope = await signEnvelope(env.SIGNING_KEY_JWK, cmd);
  // Mark dispatched BEFORE pushing: the agent can answer over /v1/results within ms, and writing
  // "dispatched" afterwards would overwrite its succeeded/failed state.
  await env.DB.prepare("UPDATE actions SET expires_at=? WHERE id=?").bind(cmd.expires_at, action.id).run();
  await setActionState(env, action.id, "dispatched");
  try {
    const { delivered } = await hostStub(env, action.host_id).pushCommand(cmd.id, envelope, now + ttl * 1000);
    await audit(env, { actor, event: "action.dispatched", incident_id: action.incident_id, host_id: action.host_id, action_id: action.id, detail: { action: action.action, params, pushed_over_ws: delivered } });
    return (await getAction(env, action.id)) ?? action;
  } catch (e) {
    logError("dispatch failed", e, { action_id: action.id });
    return await setActionState(env, action.id, "failed", { error: "dispatch: " + errMsg(e) });
  }
}

export async function signalWorkflow(env: Env, incidentId: string | null, type: string, payload: Record<string, unknown>): Promise<void> {
  if (!incidentId) return;
  try {
    const inc = await env.DB.prepare("SELECT workflow_id FROM incidents WHERE id=?").bind(incidentId).first<{ workflow_id: string | null }>();
    if (!inc?.workflow_id) return;
    const inst = await env.INVESTIGATION.get(inc.workflow_id);
    await inst.sendEvent({ type, payload });
  } catch (e) {
    // Workflow may be finished or not waiting yet; it re-reads D1 state, so this is non-fatal.
    console.log(JSON.stringify({ message: "signalWorkflow skipped", type, incident_id: incidentId, error: errMsg(e) }));
  }
}
