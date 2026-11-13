/** Thin typed wrapper over env.AI.run that routes through AI Gateway. The result is treated as unknown and parsed defensively. */
export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

function gatewayOpts(env: Env): { gateway?: { id: string } } {
  return env.AI_GATEWAY_ID ? { gateway: { id: env.AI_GATEWAY_ID } } : {};
}

export async function aiRunRaw(env: Env, model: string, input: Record<string, unknown>): Promise<unknown> {
  // Model is configurable (AI_MODEL var), so it cannot be a literal in AiModels; the binding validates it at runtime.
  const run = env.AI.run.bind(env.AI) as (m: string, i: Record<string, unknown>, o?: Record<string, unknown>) => Promise<unknown>;
  return run(model, input, gatewayOpts(env));
}

export async function runChat(
  env: Env,
  messages: ChatMessage[],
  opts: { jsonSchema?: Record<string, unknown>; maxTokens?: number; temperature?: number } = {},
): Promise<unknown> {
  const input: Record<string, unknown> = {
    messages,
    max_tokens: opts.maxTokens ?? 2048,
    temperature: opts.temperature ?? 0.1,
  };
  if (opts.jsonSchema) input.response_format = { type: "json_schema", json_schema: opts.jsonSchema };
  return aiRunRaw(env, env.AI_MODEL, input);
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
