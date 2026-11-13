import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { AGENT_SYSTEM_PROMPT, analyze, AnalystError, buildUserPrompt, type AnalystOutput } from "../ai/analyst";
import { loadContext } from "../ai/context";
import { extractAssistantText, parseToolCalls, runChat, type ParsedToolCall } from "../ai/runner";
import { actionState, completeWait, isTerminal, pendingApprovedIds, runTool, toolSpecs, type ToolOutcome, type WaitSpec } from "../ai/tools";
import { getTurn, injectSeq, insertTurn, loadTurns, MAX_CALLS_PER_TURN, toMessages, turnBase } from "../ai/transcript";
import { rememberIncident } from "../ai/memory";
import { recordReview } from "../lib/reviews";
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
// Loop budgets (AGENT_MODE=loop). Wall time excludes approval waits.
export const MAX_TOOL_CALLS = 30;
export const MAX_TURNS = 20;
/** Fresh allowance after approvals come back, so a long evidence sweep can never leave containment unverified. */
export const VERIFY_TOOL_CALLS = 10;
export const VERIFY_TURNS = 5;
export const LOOP_WALL_MS = 20 * 60 * 1000;
export const EVIDENCE_WAIT = "60 seconds";
export const MAX_EVIDENCE_WAITS = 15;
export const NUDGE_TEXT = "You did not call a tool. Call a tool, or call finish if you are done.";
export const BUDGET_TEXT = "budget exhausted: call finish now";

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

export async function analyzeStep(env: Env, incidentId: string, step: "triage" | "reanalyze" | "final", round: number, runId = ""): Promise<ReviewRef> {
  const inc = await getIncident(env, incidentId);
  const empty: ReviewRef = { skipped: true, review_id: "", verdict: "", severity: "", confidence: 0 };
  if (!inc || isClosed(inc.status)) return empty;
  // Keyed per workflow run: a run started for new anomalies must analyze afresh, not reuse an old run's triage.
  const reviewId = await deterministicUuid(`review:${incidentId}:${runId}:${step}:${round}`);
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
  await recordReview(env, incidentId, { reviewId, step, round, model: res.model, promptHash: res.promptHash, output: o, auditExtra: { repaired: res.repaired } });
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
  // resolved = containment succeeded AND the AI verified it: it claims verified=true AND an evidence check actually
  // succeeded after the last containment (the claim alone is not trusted). A human confirms resolved -> closed_tp.
  const checked = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM actions e WHERE e.incident_id=?1 AND e.action='collect_evidence' AND e.state='succeeded' AND e.created_at >
       (SELECT MAX(c.updated_at) FROM actions c WHERE c.incident_id=?1 AND c.state='succeeded' AND c.action IN ('kill_process','block_ip','disable_user','quarantine_file','isolate_host'))`,
  ).bind(incidentId).first<{ n: number }>();
  if ((contained?.n ?? 0) > 0) status = out?.verified === true && (checked?.n ?? 0) > 0 ? "resolved" : "contained";
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

// ---------------- loop step bodies (AGENT_MODE=loop; each idempotent) ----------------

export async function initLoopStep(env: Env, incidentId: string, runId: string): Promise<{ skipped: boolean; startedAt: number }> {
  const inc = await getIncident(env, incidentId);
  if (!inc || isClosed(inc.status)) return { skipped: true, startedAt: 0 };
  if ((await getAutonomy(env, inc.host_id)) === "paused") {
    await audit(env, { actor: "ai", event: "ai.skipped_paused", incident_id: incidentId, host_id: inc.host_id });
    return { skipped: true, startedAt: 0 };
  }
  if (!(await getTurn(env, runId, 0))) {
    const ctx = await loadContext(env, incidentId, "triage", 0);
    await insertTurn(env, { incident_id: incidentId, run_id: runId, seq: 0, role: "user", content: { text: buildUserPrompt(ctx, undefined, true) } });
  }
  return { skipped: false, startedAt: Date.now() };
}

export interface TurnResult {
  skipped: boolean;
  now: number;
  calls: ParsedToolCall[];
}

export async function turnStep(env: Env, incidentId: string, runId: string, n: number, opts: { inject: "nudge" | "budget" | null; force: boolean }): Promise<TurnResult> {
  const inc = await getIncident(env, incidentId);
  if (!inc || isClosed(inc.status) || (await getAutonomy(env, inc.host_id)) === "paused") return { skipped: true, now: Date.now(), calls: [] };
  if (opts.inject) await insertTurn(env, { incident_id: incidentId, run_id: runId, seq: injectSeq(n), role: "user", content: { text: opts.inject === "budget" ? BUDGET_TEXT : NUDGE_TEXT } });
  if (!(await getTurn(env, runId, turnBase(n)))) {
    const messages = toMessages(await loadTurns(env, runId));
    const raw = await runChat(env, messages, {
      tools: toolSpecs(opts.force ? "finish" : undefined),
      toolChoice: opts.force ? { type: "function", function: { name: "finish" } } : "auto",
      maxTokens: 3000,
    });
    const calls = parseToolCalls(raw, `call_${n}`).slice(0, MAX_CALLS_PER_TURN);
    const text = truncate(extractAssistantText(raw), 4000);
    await insertTurn(env, { incident_id: incidentId, run_id: runId, seq: turnBase(n), role: "assistant", content: { ...(text ? { text } : {}), ...(calls.length ? { tool_calls: calls } : {}) } });
    await audit(env, { actor: "ai", event: "ai.turn", incident_id: incidentId, host_id: inc.host_id, detail: { run_id: runId, turn: n, tool_calls: calls.map((c) => c.name), forced: opts.force } });
  }
  const row = await getTurn(env, runId, turnBase(n));
  const stored = safeJson<{ tool_calls?: ParsedToolCall[] }>(row?.content_json, {});
  return { skipped: false, now: Date.now(), calls: stored.tool_calls ?? [] };
}

export interface ToolStepResult {
  done: boolean;
  wait?: WaitSpec;
}

async function writeToolTurn(env: Env, incidentId: string, runId: string, n: number, i: number, call: ParsedToolCall, o: ToolOutcome): Promise<void> {
  await insertTurn(env, {
    incident_id: incidentId, run_id: runId, seq: turnBase(n) + 1 + i, role: "tool", tool_name: call.name, tool_call_id: call.id,
    content: { ...(o.error !== undefined ? { error: o.error } : { result: o.result ?? null }), ...(o.action_id ? { action_id: o.action_id } : {}) },
  });
}

export async function toolStep(env: Env, incidentId: string, runId: string, n: number, i: number, call: ParsedToolCall, over: boolean): Promise<ToolStepResult> {
  const prior = await getTurn(env, runId, turnBase(n) + 1 + i);
  if (prior) return { done: call.name === "finish" && !safeJson<{ error?: string }>(prior.content_json, {}).error };
  const inc = (await getIncident(env, incidentId))!;
  const o = over && call.name !== "finish"
    ? ({ error: "tool-call budget exhausted: call finish now" } as ToolOutcome)
    : await runTool({ env, incidentId, hostId: inc.host_id, runId, n, i }, call.name, call.arguments);
  await audit(env, { actor: "ai", event: "tool.called", incident_id: incidentId, host_id: inc.host_id, action_id: o.action_id ?? null, detail: { run_id: runId, turn: n, tool: call.name, ok: o.error === undefined, error: o.error } });
  if (o.wait) return { done: false, wait: o.wait };
  await writeToolTurn(env, incidentId, runId, n, i, call, o);
  return { done: !!o.done && o.error === undefined };
}

export async function toolDoneStep(env: Env, incidentId: string, runId: string, n: number, i: number, call: ParsedToolCall, wait: WaitSpec): Promise<boolean> {
  await writeToolTurn(env, incidentId, runId, n, i, call, await completeWait(env, incidentId, wait));
  return true;
}

/** The review finalize should read: this run's finish() review, else the last known review of the incident. */
export async function loopReviewRef(env: Env, incidentId: string, runId: string): Promise<ReviewRef> {
  const finalId = await deterministicUuid(`review:${incidentId}:${runId}:final:0`);
  const row =
    (await env.DB.prepare("SELECT id, output_json FROM ai_reviews WHERE id=?").bind(finalId).first<{ id: string; output_json: string }>()) ??
    (await env.DB.prepare("SELECT id, output_json FROM ai_reviews WHERE incident_id=? AND step!='ask' ORDER BY ts DESC LIMIT 1").bind(incidentId).first<{ id: string; output_json: string }>());
  if (!row) return { skipped: true, review_id: "", verdict: "", severity: "", confidence: 0 };
  const o = safeJson<AnalystOutput>(row.output_json, null as unknown as AnalystOutput);
  return { skipped: false, review_id: row.id, verdict: o.verdict, severity: o.severity, confidence: o.confidence };
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

  /** Wait (60s slices) until an action is terminal. The evidence event is only a hint: D1 is re-read each time. */
  private async waitForAction(step: WorkflowStep, tag: string, actionId: string): Promise<void> {
    for (let k = 0; k < MAX_EVIDENCE_WAITS; k++) {
      const st = await step.do(`wait-check:${tag}:${k}`, DB_STEP_CFG, () => actionState(this.env, actionId));
      if (isTerminal(st) || st === "missing") return;
      try {
        await step.waitForEvent(`wait-evt:${tag}:${k}`, { type: "evidence", timeout: EVIDENCE_WAIT });
      } catch {
        /* timeout: loop re-reads D1 */
      }
    }
    await step.do(`wait-expire:${tag}`, DB_STEP_CFG, async () => {
      const a = await getAction(this.env, actionId);
      if (a && a.state === "dispatched") await setActionState(this.env, actionId, "expired", { error: "no result from agent before timeout" });
      return true;
    });
  }

  async run(event: Readonly<WorkflowEvent<InvestigationParams>>, step: WorkflowStep): Promise<{ status: string; rounds: number }> {
    return (this.env.AGENT_MODE ?? "loop") === "rounds" ? this.runRounds(event, step) : this.runLoop(event, step);
  }

  private async runLoop(event: Readonly<WorkflowEvent<InvestigationParams>>, step: WorkflowStep): Promise<{ status: string; rounds: number }> {
    const id = event.payload.incident_id;
    const runId = event.instanceId;
    const start = await step.do("start", DB_STEP_CFG, () => startStep(this.env, id));
    if (start.closed) return { status: "closed", rounds: 0 };
    let n = 0;
    try {
      const init = await step.do("loop-init", AI_STEP_CFG, () => initLoopStep(this.env, id, runId));
      if (init.skipped) return { status: "skipped", rounds: 0 };
      let lastNow = init.startedAt;
      let approvalWait = 0;
      let toolCalls = 0;
      let maxCalls = MAX_TOOL_CALLS;
      let maxTurns = MAX_TURNS;
      let noTool = 0;
      let forced = false;
      let forcedTurns = 0;
      let finished = false;
      for (; !finished; n++) {
        const budget = forced || toolCalls >= maxCalls || n >= maxTurns || lastNow - init.startedAt - approvalWait > LOOP_WALL_MS;
        const force = budget || noTool >= 2;
        const inject = budget && !forced ? ("budget" as const) : noTool === 1 && !force ? ("nudge" as const) : null;
        if (force) {
          forced = true;
          if (++forcedTurns > 2) break; // the model will not finish: finalize with the last known verdict
        }
        // Rpc.Serializable can't express Record<string, unknown> (tool arguments are JSON by construction)
        const t = (await step.do(`turn:${n}`, AI_STEP_CFG, () => turnStep(this.env, id, runId, n, { inject, force }) as Promise<never>)) as TurnResult;
        if (t.skipped) return { status: "skipped", rounds: n };
        lastNow = t.now;
        if (t.calls.length === 0) {
          noTool++;
          continue;
        }
        noTool = 0;
        for (let i = 0; i < t.calls.length && !finished; i++) {
          const call = t.calls[i]!;
          const over = toolCalls >= maxCalls;
          if (call.name !== "finish") toolCalls++;
          const r = await step.do(`tool:${n}:${i}`, DB_STEP_CFG, () => toolStep(this.env, id, runId, n, i, call, over));
          if (r.wait) {
            const w = r.wait;
            const tag = `${n}:${i}`;
            if (w.kind === "action") await this.waitForAction(step, tag, w.action_id);
            else {
              const t0 = await step.do(`appr-start:${tag}`, DB_STEP_CFG, async () => Date.now());
              await this.waitForApprovals(step, id, `a${tag}`);
              const t1 = await step.do(`appr-end:${tag}`, DB_STEP_CFG, async () => Date.now());
              approvalWait += t1 - t0;
              lastNow = t1;
              maxCalls = Math.max(maxCalls, toolCalls + VERIFY_TOOL_CALLS);
              maxTurns = Math.max(maxTurns, n + 1 + VERIFY_TURNS);
              const ids = await step.do(`appr-dispatched:${tag}`, DB_STEP_CFG, () => pendingApprovedIds(this.env, id));
              for (const aid of ids) await this.waitForAction(step, `${tag}:${aid.slice(0, 8)}`, aid);
            }
            await step.do(`tool-done:${tag}`, DB_STEP_CFG, () => toolDoneStep(this.env, id, runId, n, i, call, w));
          } else if (r.done) finished = true;
        }
      }
      const ref = await step.do("final-ref", DB_STEP_CFG, () => loopReviewRef(this.env, id, runId));
      const done = await step.do("finalize", DB_STEP_CFG, () => finalizeStep(this.env, id, ref));
      await step.do("remember", DB_STEP_CFG, () => memoryStep(this.env, id));
      return { status: done.status, rounds: n };
    } catch (e) {
      logError("investigation failed", e, { incident_id: id, analyst_error: e instanceof AnalystError });
      return this.recordFailure(step, id, errMsg(e), n);
    }
  }

  private async recordFailure(step: WorkflowStep, id: string, msg: string, rounds: number): Promise<{ status: string; rounds: number }> {
    await step.do("record-failure", DB_STEP_CFG, async () => {
      await audit(this.env, { actor: "ai", event: "ai.failed", incident_id: id, detail: { error: msg } });
      await this.env.DB.prepare("UPDATE incidents SET status='open', updated_at=? WHERE id=? AND status NOT LIKE 'closed%'").bind(nowIso(), id).run();
      await publishIncident(this.env, id);
      return true;
    });
    return { status: "failed", rounds };
  }

  /** Legacy fixed-rounds path (AGENT_MODE=rounds), kept for rollback. */
  private async runRounds(event: Readonly<WorkflowEvent<InvestigationParams>>, step: WorkflowStep): Promise<{ status: string; rounds: number }> {
    const id = event.payload.incident_id;
    const start = await step.do("start", DB_STEP_CFG, () => startStep(this.env, id));
    if (start.closed) return { status: "closed", rounds: 0 };

    let stepName: "triage" | "reanalyze" = "triage";
    let round = 0;
    let last: ReviewRef | null = null;
    try {
      for (;;) {
        const tag = `r${round}`;
        const review = await step.do(`${stepName}:${tag}`, AI_STEP_CFG, () => analyzeStep(this.env, id, stepName, round, event.instanceId));
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
      const fin = await step.do("final", AI_STEP_CFG, () => analyzeStep(this.env, id, "final", round + 1, event.instanceId));
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
