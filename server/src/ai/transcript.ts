import { publish } from "../lib/fleet";
import { deterministicUuid, nowIso, safeJson } from "../lib/util";
import { AGENT_SYSTEM_PROMPT, untrusted } from "./analyst";
import type { ChatMessage } from "./runner";
import { randomToken } from "../lib/util";

/** Deterministic seq layout per turn n: assistant at base(n), tool results at base+1.., injected user message at base(n)-1. Seq 0 = initial prompt. */
export const SEQ_STRIDE = 10;
export const MAX_CALLS_PER_TURN = 8;
export const turnBase = (n: number) => 1 + n * SEQ_STRIDE;
export const injectSeq = (n: number) => n * SEQ_STRIDE;

export interface TurnContent {
  text?: string;
  tool_calls?: { id: string; name: string; arguments: Record<string, unknown> }[];
  result?: unknown;
  error?: string;
  action_id?: string;
}
export interface TurnRow {
  id: string;
  incident_id: string;
  run_id: string;
  seq: number;
  role: "user" | "assistant" | "tool";
  tool_name: string | null;
  tool_call_id: string | null;
  content_json: string;
  ts: string;
}

/** INSERT OR IGNORE keyed (run_id, seq): a retried step never duplicates a turn. Returns true if newly inserted. */
export async function insertTurn(env: Env, t: { incident_id: string; run_id: string; seq: number; role: TurnRow["role"]; tool_name?: string | null; tool_call_id?: string | null; content: TurnContent }): Promise<boolean> {
  const id = await deterministicUuid(`turn:${t.run_id}:${t.seq}`);
  const res = await env.DB.prepare("INSERT OR IGNORE INTO agent_turns(id, incident_id, run_id, seq, role, tool_name, tool_call_id, content_json, ts) VALUES (?,?,?,?,?,?,?,?,?)")
    .bind(id, t.incident_id, t.run_id, t.seq, t.role, t.tool_name ?? null, t.tool_call_id ?? null, JSON.stringify(t.content), nowIso()).run();
  if (!res.meta.changes) return false;
  const row = await getTurn(env, t.run_id, t.seq);
  if (row) await publish(env, "agent_turn", row as unknown as Record<string, unknown>);
  return true;
}

export const getTurn = (env: Env, runId: string, seq: number) =>
  env.DB.prepare("SELECT * FROM agent_turns WHERE run_id=? AND seq=?").bind(runId, seq).first<TurnRow>();

export async function loadTurns(env: Env, runId: string): Promise<TurnRow[]> {
  return (await env.DB.prepare("SELECT * FROM agent_turns WHERE run_id=? ORDER BY seq").bind(runId).all<TurnRow>()).results;
}

/** Rebuild the model's messages from D1. Tool results are wrapped as untrusted data; errors (server text) go back plain. */
export function toMessages(turns: TurnRow[], nonce = randomToken(6)): ChatMessage[] {
  const msgs: ChatMessage[] = [{ role: "system", content: AGENT_SYSTEM_PROMPT }];
  for (const t of turns) {
    const c = safeJson<TurnContent>(t.content_json, {});
    if (t.role === "user") msgs.push({ role: "user", content: c.text ?? "" });
    else if (t.role === "assistant") {
      const m: ChatMessage = { role: "assistant", content: c.text ?? "" };
      if (c.tool_calls?.length) m.tool_calls = c.tool_calls.map((tc) => ({ id: tc.id, type: "function", function: { name: tc.name, arguments: JSON.stringify(tc.arguments) } }));
      msgs.push(m);
    } else {
      const body = c.error !== undefined ? JSON.stringify({ error: c.error }) : untrusted(`tool:${t.tool_name ?? "?"}`, JSON.stringify(c.result ?? null).slice(0, 12_000), nonce);
      msgs.push({ role: "tool", tool_call_id: t.tool_call_id ?? "", content: body });
    }
  }
  return msgs;
}
