import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { analyze, AnalystError, type AnalystOutput } from "../ai/analyst";
import { loadContext } from "../ai/context";
import { rememberIncident } from "../ai/memory";
import { audit } from "../lib/audit";
import { createAction, dispatchAction, getAction, getAutonomy, PROPOSAL_TTL_S, setActionState } from "../lib/actions";
import { publish } from "../lib/fleet";
import { getIncident, isClosed, publishIncident } from "../lib/incidents";
import { deterministicUuid, errMsg, logError, nowIso, safeJson, truncate } from "../lib/util";
import { buildGateContext, gateBatch, type GateDecision } from "../policy/gate";
import { effectiveThresholds, getServerEndpoints } from "../policy/service";
import { SEV_RANK, type ActionRow, type Severity } from "../types";

export interface InvestigationParams {
  incident_id: string;
}

export const MAX_REANALYZE_ROUNDS = 3;
export const EVIDENCE_TIMEOUT = "5 minutes";
export const APPROVAL_TIMEOUT = "24 hours";

const AI_STEP_CFG = { retries: { limit: 2, delay: "10 seconds", backoff: "exponential" }, timeout: "4 minutes" } as const;
const DB_STEP_CFG = { retries: { limit: 3, delay: "2 seconds", backoff: "exponential" }, timeout: "1 minute" } as const;

export interface ReviewRef {
  skipped: boolean;
  review_id: string;
  verdict: string;
  severity: string;
  confidence: number;
}
export interface GateRef {
  approved: string[];
  proposed: string[];
  rejected: number;
}

// ---------------- step bodies (exported for tests; each is idempotent) ----------------

export async function startStep(env: Env, incidentId: string): Promise<{ closed: boolean }> {
  const inc = await getIncident(env, incidentId);
  if (!inc || isClosed(inc.status)) return { closed: true };
  await env.DB.prepare("UPDATE incidents SET status='investigating', updated_at=? WHERE id=? AND status='open'").bind(nowIso(), incidentId).run();
  await publishIncident(env, incidentId);
  return { closed: false };
}

export async function analyzeStep(env: Env, incidentId: string, step: "triage" | "reanalyze" | "final", round: number): Promise<ReviewRef> {
  const inc = await getIncident(env, incidentId);
  const empty: ReviewRef = { skipped: true, review_id: "", verdict: "", severity: "", confidence: 0 };
  if (!inc || isClosed(inc.status)) return empty;
  const reviewId = await deterministicUuid(`review:${incidentId}:${step}:${round}`);
  const existing = await env.DB.prepare("SELECT output_json FROM ai_reviews WHERE id=?").bind(reviewId).first<{ output_json: string }>();
  if (existing) {
    const o = safeJson<AnalystOutput>(existing.output_json, null as unknown as AnalystOutput);
    return { skipped: false, review_id: reviewId, verdict: o.verdict, severity: o.severity, confidence: o.confidence };
  }
  if ((await getAutonomy(env, inc.host_id)) === "paused") {
    await audit(env, { actor: "ai", event: "ai.skipped_paused", incident_id: incidentId, host_id: inc.host_id });
    return empty;
  }
  const ctx = await loadContext(env, incidentId, step, round);
  const res = await analyze(env, ctx);
  const o = res.output;
  const ts = nowIso();
  await env.DB.prepare("INSERT OR IGNORE INTO ai_reviews(id, incident_id, step, round, model, prompt_hash, output_json, gate_json, ts) VALUES (?,?,?,?,?,?,?,NULL,?)")
    .bind(reviewId, incidentId, step, round, res.model, res.promptHash, JSON.stringify(o), ts).run();
  const tags = [...new Set([...safeJson<string[]>(inc.attack_tags_json, []), ...o.attack_tags])].slice(0, 40);
  await env.DB.prepare(
    "UPDATE incidents SET verdict=?, severity=?, confidence=?, attack_tags_json=?, status=CASE WHEN status='open' THEN 'investigating' ELSE status END, updated_at=? WHERE id=? AND status NOT LIKE 'closed%'",
  ).bind(o.verdict, o.severity, o.confidence, JSON.stringify(tags), ts, incidentId).run();
  for (const ioc of o.iocs.slice(0, 30)) {
    // AI-extracted IOCs are NOT pushed to agents (watch=0) until a human confirms the incident.
    await env.DB.prepare("INSERT OR IGNORE INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES (?,?,?,?,?,0,?)")
      .bind(crypto.randomUUID(), ioc.type, ioc.type === "sha256" ? ioc.value.toLowerCase() : ioc.value, "ai", incidentId, ts).run();
  }
  await audit(env, { actor: "ai", event: `ai.${step}`, incident_id: incidentId, host_id: inc.host_id, detail: { review_id: reviewId, verdict: o.verdict, severity: o.severity, confidence: o.confidence, requests: o.requests.length, repaired: res.repaired } });
  const row = await env.DB.prepare("SELECT * FROM ai_reviews WHERE id=?").bind(reviewId).first<Record<string, unknown>>();
  if (row) await publish(env, "ai_review", row);
  await publishIncident(env, incidentId);
  return { skipped: false, review_id: reviewId, verdict: o.verdict, severity: o.severity, confidence: o.confidence };
}

export async function gateStep(env: Env, incidentId: string, reviewId: string, isFinal: boolean): Promise<GateRef> {
  const inc = (await getIncident(env, incidentId))!;
  const rev = await env.DB.prepare("SELECT output_json, gate_json FROM ai_reviews WHERE id=?").bind(reviewId).first<{ output_json: string; gate_json: string | null }>();
  if (!rev) throw new Error("review missing");
  const out = safeJson<AnalystOutput>(rev.output_json, null as unknown as AnalystOutput);
  const requests = out.requests ?? [];
  let decisions: GateDecision[];
  if (isFinal) {
    decisions = requests.map((r) => ({ action: r.action, accepted: false, tier: 1 as const, kind: "command" as const, reason: "final step: requests are ignored", normalizedParams: {}, requiresApproval: false }));
  } else {
    const [mode, endpoints, thresholds] = await Promise.all([getAutonomy(env, inc.host_id), getServerEndpoints(env), effectiveThresholds(env, inc.host_id)]);
    const ctx = await buildGateContext(env, { hostId: inc.host_id, source: "ai", mode, thresholds, serverEndpoints: endpoints, requests });
    decisions = gateBatch(requests, ctx);
  }
  await env.DB.prepare("UPDATE ai_reviews SET gate_json=? WHERE id=?").bind(JSON.stringify(decisions.map((d) => ({ action: d.action, tier: d.tier, accepted: d.accepted, reason: d.reason, requires_approval: d.requiresApproval }))), reviewId).run();
  const approved: string[] = [];
  const proposed: string[] = [];
  let rejected = 0;
  for (let i = 0; i < decisions.length; i++) {
    const d = decisions[i]!;
    const req = requests[i]!;
    const id = await deterministicUuid(`action:${reviewId}:${i}`);
    if (!d.accepted) {
      rejected++;
      const raw = truncate(JSON.stringify(req.params ?? {}), 2000);
      await createAction(env, {
        id, incident_id: incidentId, host_id: inc.host_id, action: String(req.action).slice(0, 64),
        params: d.normalizedParams && Object.keys(d.normalizedParams).length ? d.normalizedParams : safeJson<Record<string, unknown>>(raw, { _truncated: raw }),
        tier: d.tier, kind: d.kind, state: "rejected", proposed_by: "ai", rationale: req.reason, reject_reason: d.reason,
      });
      await audit(env, { actor: "ai", event: "gate.rejected", incident_id: incidentId, host_id: inc.host_id, action_id: id, detail: { action: req.action, reason: d.reason } });
      continue;
    }
    const row = await createAction(env, {
      id, incident_id: incidentId, host_id: inc.host_id, action: d.action, params: d.normalizedParams, tier: d.tier, kind: d.kind,
      state: d.requiresApproval ? "proposed" : "approved", proposed_by: "ai", rationale: req.reason,
      expires_at: d.requiresApproval ? new Date(Date.now() + PROPOSAL_TTL_S * 1000).toISOString() : null,
    });
    if (row.state === "proposed") proposed.push(id);
    else if (row.state === "approved") approved.push(id);
  }
  return { approved, proposed, rejected };
}

export async function dispatchStep(env: Env, ids: string[]): Promise<number> {
  let n = 0;
  for (const id of ids) {
    const a = await getAction(env, id);
    if (a && a.state === "approved") {
      await dispatchAction(env, a, "ai");
      n++;
    }
  }
  return n;
}

export async function countByState(env: Env, incidentId: string, state: string): Promise<number> {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM actions WHERE incident_id=? AND state=?").bind(incidentId, state).first<{ n: number }>();
  return r?.n ?? 0;
}

export async function setAwaitingApproval(env: Env, incidentId: string): Promise<void> {
  await env.DB.prepare("UPDATE incidents SET status='awaiting_approval', updated_at=? WHERE id=? AND status NOT LIKE 'closed%'").bind(nowIso(), incidentId).run();
  await publishIncident(env, incidentId);
}

export async function resumeInvestigating(env: Env, incidentId: string): Promise<void> {
  await env.DB.prepare("UPDATE incidents SET status='investigating', updated_at=? WHERE id=? AND status='awaiting_approval'").bind(nowIso(), incidentId).run();
  await publishIncident(env, incidentId);
}

export async function expireProposals(env: Env, incidentId: string): Promise<number> {
  const rows = (await env.DB.prepare("SELECT * FROM actions WHERE incident_id=? AND state='proposed'").bind(incidentId).all<ActionRow>()).results;
  for (const a of rows) {
    await setActionState(env, a.id, "expired", { error: "approval timeout" });
    await audit(env, { actor: "system", event: "action.expired", incident_id: incidentId, host_id: a.host_id, action_id: a.id });
  }
  await env.DB.prepare("UPDATE incidents SET status='open', updated_at=? WHERE id=? AND status='awaiting_approval'").bind(nowIso(), incidentId).run();
  await publishIncident(env, incidentId);
  return rows.length;
}

export async function expireStaleDispatched(env: Env, incidentId: string): Promise<number> {
  const rows = (await env.DB.prepare("SELECT * FROM actions WHERE incident_id=? AND state='dispatched'").bind(incidentId).all<ActionRow>()).results;
  for (const a of rows) await setActionState(env, a.id, "expired", { error: "no result from agent before timeout" });
  return rows.length;
}

export async function finalizeStep(env: Env, incidentId: string, review: ReviewRef): Promise<{ status: string }> {
  const inc = await getIncident(env, incidentId);
  if (!inc || isClosed(inc.status)) return { status: inc?.status ?? "missing" };
  const rev = review.skipped ? null : await env.DB.prepare("SELECT output_json FROM ai_reviews WHERE id=?").bind(review.review_id).first<{ output_json: string }>();
  const out = rev ? safeJson<AnalystOutput>(rev.output_json, null as unknown as AnalystOutput) : null;
  const contained = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM actions WHERE incident_id=? AND state='succeeded' AND action IN ('kill_process','block_ip','disable_user','quarantine_file','isolate_host')",
  ).bind(incidentId).first<{ n: number }>();
  let status = "open";
  if ((contained?.n ?? 0) > 0) status = "contained";
  else if (out && out.verdict === "benign" && out.confidence >= 0.7) status = "closed_benign";
  const now = nowIso();
  await env.DB.prepare(
    "UPDATE incidents SET status=?, ai_summary=COALESCE(?, ai_summary), updated_at=?, closed_at=CASE WHEN ? LIKE 'closed%' THEN ? ELSE closed_at END WHERE id=? AND status NOT LIKE 'closed%'",
  ).bind(status, out?.rationale ?? null, now, status, now, incidentId).run();
  await audit(env, { actor: "ai", event: "incident.final", incident_id: incidentId, host_id: inc.host_id, detail: { status, verdict: out?.verdict, confidence: out?.confidence } });
  await publishIncident(env, incidentId);
  return { status };
}

export async function memoryStep(env: Env, incidentId: string): Promise<boolean> {
  const inc = await getIncident(env, incidentId);
  if (!inc) return false;
  const rules = (await env.DB.prepare("SELECT DISTINCT rule_id FROM anomalies WHERE incident_id=?").bind(incidentId).all<{ rule_id: string }>()).results.map((r) => r.rule_id);
  const summary = inc.ai_summary ?? inc.title;
  return rememberIncident(
    env,
    { incident_id: incidentId, host_id: inc.host_id, title: truncate(inc.title, 200), verdict: inc.verdict ?? "", label: "", severity: inc.severity, summary: truncate(summary, 600), rule_ids: rules.join(",").slice(0, 500) },
    `${inc.title}\n${summary}\n${safeJson<string[]>(inc.attack_tags_json, []).join(" ")}`,
  );
}

// ---------------- the workflow ----------------

export class InvestigationWorkflow extends WorkflowEntrypoint<Env, InvestigationParams> {
  private async waitForResults(step: WorkflowStep, id: string, tag: string): Promise<void> {
    for (let k = 0; k < 12; k++) {
      const n = await step.do(`outstanding:${tag}:${k}`, DB_STEP_CFG, () => countByState(this.env, id, "dispatched"));
      if (n === 0) return;
      try {
        await step.waitForEvent(`results:${tag}:${k}`, { type: "evidence", timeout: EVIDENCE_TIMEOUT });
      } catch {
        await step.do(`expire-dispatched:${tag}`, DB_STEP_CFG, () => expireStaleDispatched(this.env, id));
        return;
      }
    }
  }

  private async waitForApprovals(step: WorkflowStep, id: string, tag: string): Promise<void> {
    await step.do(`await-approval:${tag}`, DB_STEP_CFG, async () => {
      if ((await countByState(this.env, id, "proposed")) > 0) await setAwaitingApproval(this.env, id);
      return true;
    });
    for (let k = 0; k < 20; k++) {
      const n = await step.do(`pending-approvals:${tag}:${k}`, DB_STEP_CFG, () => countByState(this.env, id, "proposed"));
      if (n === 0) break;
      try {
        await step.waitForEvent(`approval:${tag}:${k}`, { type: "approval", timeout: APPROVAL_TIMEOUT });
      } catch {
        await step.do(`approval-timeout:${tag}`, DB_STEP_CFG, () => expireProposals(this.env, id));
        break;
      }
    }
    await step.do(`resume:${tag}`, DB_STEP_CFG, async () => {
      await resumeInvestigating(this.env, id);
      return true;
    });
  }

  async run(event: Readonly<WorkflowEvent<InvestigationParams>>, step: WorkflowStep): Promise<{ status: string; rounds: number }> {
    const id = event.payload.incident_id;
    const start = await step.do("start", DB_STEP_CFG, () => startStep(this.env, id));
    if (start.closed) return { status: "closed", rounds: 0 };

    let stepName: "triage" | "reanalyze" = "triage";
    let round = 0;
    let last: ReviewRef | null = null;
    try {
      for (;;) {
        const tag = `r${round}`;
        const review = await step.do(`${stepName}:${tag}`, AI_STEP_CFG, () => analyzeStep(this.env, id, stepName, round));
        if (review.skipped) return { status: "skipped", rounds: round };
        last = review;
        const g = await step.do(`gate:${tag}`, DB_STEP_CFG, () => gateStep(this.env, id, review.review_id, false));
        await step.do(`dispatch:${tag}`, DB_STEP_CFG, () => dispatchStep(this.env, g.approved));
        if (g.proposed.length > 0) await this.waitForApprovals(step, id, tag);
        await this.waitForResults(step, id, tag);
        const acted = g.approved.length + g.proposed.length > 0;
        if (!acted || round >= MAX_REANALYZE_ROUNDS) break;
        round++;
        stepName = "reanalyze";
      }
      const fin = await step.do("final", AI_STEP_CFG, () => analyzeStep(this.env, id, "final", round + 1));
      if (!fin.skipped) {
        await step.do("final-gate", DB_STEP_CFG, () => gateStep(this.env, id, fin.review_id, true));
        last = fin;
      }
      const done = await step.do("finalize", DB_STEP_CFG, () => finalizeStep(this.env, id, last!));
      await step.do("remember", DB_STEP_CFG, () => memoryStep(this.env, id));
      return { status: done.status, rounds: round };
    } catch (e) {
      const msg = errMsg(e);
      logError("investigation failed", e, { incident_id: id, analyst_error: e instanceof AnalystError });
      await step.do("record-failure", DB_STEP_CFG, async () => {
        await audit(this.env, { actor: "ai", event: "ai.failed", incident_id: id, detail: { error: msg } });
        await this.env.DB.prepare("UPDATE incidents SET status='open', updated_at=? WHERE id=? AND status NOT LIKE 'closed%'").bind(nowIso(), id).run();
        await publishIncident(this.env, id);
        return true;
      });
      return { status: "failed", rounds: round };
    }
  }
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}
