/** Thin typed wrapper over env.AI.run that routes through AI Gateway. The result is treated as unknown and parsed defensively. */
export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** assistant turns that called tools (OpenAI shape) */
  tool_calls?: { id: string; type: "function"; function: { name: string; arguments: string } }[];
  /** tool results */
  tool_call_id?: string;
}

export interface ToolSpec {
  type: "function";
  function: { name: string; description: string; parameters: Record<string, unknown> };
}
export type ToolChoice = "auto" | "none" | { type: "function"; function: { name: string } };

export interface ParsedToolCall {
  id: string;
  name: string;
  /** a JSON object, or `{ _unparsed: raw }` when the model sent arguments that are not a JSON object */
  arguments: Record<string, unknown>;
}

function gatewayOpts(env: Env): { gateway?: { id: string } } {
  return env.AI_GATEWAY_ID ? { gateway: { id: env.AI_GATEWAY_ID } } : {};
}

export async function aiRunRaw(env: Env, model: string, input: Record<string, unknown>): Promise<unknown> {
  // Model is configurable (AI_MODEL var), so it cannot be a literal in AiModels; the binding validates it at runtime.
  const run = env.AI.run.bind(env.AI) as (m: string, i: Record<string, unknown>, o?: Record<string, unknown>) => Promise<unknown>;
  const opts = gatewayOpts(env);
  if (!opts.gateway) return run(model, input);
  try {
    return await run(model, input, opts);
  } catch (err) {
    // A missing/misconfigured gateway (e.g. code 2001) must not blind the SOC: fall back to a direct call.
    if (!isGatewayConfigError(err)) throw err;
    console.warn(JSON.stringify({ message: "AI Gateway unavailable, calling Workers AI directly", gateway: env.AI_GATEWAY_ID, error: String(err) }));
    return run(model, input);
  }
}

function isGatewayConfigError(err: unknown): boolean {
  const s = String((err as { message?: string })?.message ?? err);
  return /AiGateway|\b2001\b|configure AI Gateway/i.test(s);
}

export async function runChat(
  env: Env,
  messages: ChatMessage[],
  opts: { jsonSchema?: Record<string, unknown>; maxTokens?: number; temperature?: number; tools?: ToolSpec[]; toolChoice?: ToolChoice } = {},
): Promise<unknown> {
  const input: Record<string, unknown> = {
    messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.1,
  };
  if (opts.jsonSchema) input.response_format = { type: "json_schema", json_schema: opts.jsonSchema };
  if (opts.tools?.length) {
    input.tools = opts.tools;
    if (opts.toolChoice) input.tool_choice = opts.toolChoice;
  }
  return aiRunRaw(env, env.AI_MODEL, input);
}

/** Tool calls from `choices[0].message.tool_calls` (OpenAI) or a legacy top-level `tool_calls`; arguments may be a JSON string or an object. */
export function parseToolCalls(out: unknown, idPrefix = "call"): ParsedToolCall[] {
  if (!out || typeof out !== "object") return [];
  const o = out as Record<string, unknown>;
  const msg = Array.isArray(o.choices) ? (o.choices[0] as { message?: { tool_calls?: unknown } } | undefined)?.message : undefined;
  const raw = Array.isArray(msg?.tool_calls) ? msg!.tool_calls : Array.isArray(o.tool_calls) ? o.tool_calls : [];
  const calls: ParsedToolCall[] = [];
  (raw as unknown[]).forEach((c, i) => {
    if (!c || typeof c !== "object") return;
    const r = c as { id?: unknown; name?: unknown; arguments?: unknown; function?: { name?: unknown; arguments?: unknown } };
    const name = r.function?.name ?? r.name;
    if (typeof name !== "string" || !name) return;
    let args: unknown = r.function ? r.function.arguments : r.arguments;
    if (typeof args === "string") {
      const str: string = args;
      try {
        args = str.trim() === "" ? {} : JSON.parse(str);
      } catch {
        args = { _unparsed: str.slice(0, 2000) };
      }
    }
    if (args === undefined || args === null) args = {};
    if (typeof args !== "object" || Array.isArray(args)) args = { _unparsed: JSON.stringify(args).slice(0, 2000) };
    let id = typeof r.id === "string" && /^[\w.\-]{1,64}$/.test(r.id) ? r.id : `${idPrefix}_${i}`;
    if (calls.some((x) => x.id === id)) id = `${idPrefix}_${i}`;
    calls.push({ id, name: name.slice(0, 64), arguments: args as Record<string, unknown> });
  });
  return calls;
}

/** Assistant prose from a chat response (string content only). */
export function extractAssistantText(out: unknown): string {
  const t = extractModelOutput(out);
  return typeof t === "string" ? t : "";
}

/** Extract the model's text or object from the several shapes Workers AI returns. */
export function extractModelOutput(out: unknown): unknown {
  if (typeof out === "string") return out;
  if (!out || typeof out !== "object") return null;
  const o = out as Record<string, unknown>;
  if ("response" in o && o.response !== null && o.response !== undefined) return o.response;
  const choices = o.choices;
  if (Array.isArray(choices)) {
    const msg = (choices[0] as { message?: { content?: unknown } } | undefined)?.message;
    if (msg?.content !== undefined && msg.content !== null) return msg.content;
  }
  if ("verdict" in o) return o; // already the parsed object
  return null;
}
