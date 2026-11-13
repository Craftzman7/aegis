import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import worker from "../src/index";
import { b64enc, nowIso, sha256Hex } from "../src/lib/util";
import { canonicalString } from "../src/crypto/sign";

export type AiHandler = (model: string, input: Record<string, unknown>) => unknown | Promise<unknown>;

export interface Captured {
  queued: { anomaly_id: string }[];
  workflows: { id?: string; params?: unknown }[];
  events: { id: string; type: string; payload: unknown }[];
  aiCalls: { model: string; input: Record<string, unknown> }[];
  vectors: unknown[];
}

/** Env with stubbed AI / Vectorize / Queue / Workflow (all remote or side-effecting in prod). */
export function mkEnv(aiHandler: AiHandler = () => ({ response: "{}" }), over: Record<string, unknown> = {}): { env: Env; cap: Captured } {
  const cap: Captured = { queued: [], workflows: [], events: [], aiCalls: [], vectors: [] };
  const ai = {
    run: async (model: string, input: Record<string, unknown>) => {
      cap.aiCalls.push({ model, input });
      if (model.includes("bge")) return { data: [Array.from({ length: 768 }, (_, i) => (i % 7) / 7)] };
      return aiHandler(model, input);
    },
  };
  const memory = {
    upsert: async (v: unknown[]) => { cap.vectors.push(...v); return { mutationId: "m" }; },
    query: async () => ({ matches: [], count: 0 }),
  };
  const queue = {
    send: async (b: { anomaly_id: string }) => { cap.queued.push(b); },
    sendBatch: async (msgs: { body: { anomaly_id: string } }[]) => { for (const m of msgs) cap.queued.push(m.body); },
  };
  const wf = {
    create: async (o: { id?: string; params?: unknown }) => { cap.workflows.push(o); return { id: o.id }; },
    get: async (id: string) => ({
      id,
      sendEvent: async (e: { type: string; payload: unknown }) => { cap.events.push({ id, ...e }); },
      status: async () => ({ status: "running" }),
      terminate: async () => { cap.events.push({ id, type: "terminate", payload: null }); },
    }),
  };
  const e = Object.create(env, {
    AI: { value: ai },
    MEMORY: { value: memory },
    TRIAGE: { value: queue },
    INVESTIGATION: { value: wf },
    ...Object.fromEntries(Object.entries(over).map(([k, v]) => [k, { value: v }])),
  }) as Env;
  return { env: e, cap };
}

export async function call(e: Env, req: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export interface TestHost {
  id: string;
  priv: CryptoKey;
  pubB64: string;
  req(e: Env, method: string, path: string, body?: unknown, opts?: { ts?: number; badSig?: boolean; headers?: Record<string, string> }): Promise<Response>;
}

export async function mkToken(ttlMs = 3600_000): Promise<string> {
  const token = "tok_" + crypto.randomUUID();
  await env.DB.prepare("INSERT INTO enroll_tokens(token_hash, created_by, expires_at) VALUES (?,?,?)").bind(await sha256Hex(token), "test", new Date(Date.now() + ttlMs).toISOString()).run();
  return token;
}

export async function enrollHost(e: Env, hostname = "web-1"): Promise<TestHost> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  const pubB64 = b64enc(pub);
  const token = await mkToken();
  const res = await call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body: JSON.stringify({ token, hostname, os: "ubuntu 24.04", arch: "amd64", kernel: "6.8", agent_version: "0.1.0", pubkey: pubB64 }) }));
  if (res.status !== 200) throw new Error("enroll failed " + res.status + " " + (await res.text()));
  const j = (await res.json()) as { host_id: string };
  const host: TestHost = {
    id: j.host_id,
    priv: kp.privateKey,
    pubB64,
    async req(env2, method, path, body, opts = {}) {
      const raw = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
      const ts = opts.ts ?? Math.floor(Date.now() / 1000);
      const canonical = await canonicalString(method, path, ts, raw);
      let sig = b64enc(new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode(canonical))));
      if (opts.badSig) sig = b64enc(new Uint8Array(64));
      return call(env2, new Request("https://aegis.test" + path, { method, body: method === "GET" ? undefined : raw, headers: { "X-Aegis-Host": j.host_id, "X-Aegis-Ts": String(ts), "X-Aegis-Sig": sig, "content-type": "application/json", ...(opts.headers ?? {}) } }));
    },
  };
  return host;
}

export function mkAnomaly(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: crypto.randomUUID(), ts: nowIso(), rule_id: "native:ssh_bruteforce", rule_source: "native", rule_title: "SSH brute force",
    category: "auth", severity: "medium", fingerprint: "f".repeat(64), summary: "25 failed ssh logins from 198.51.100.7",
    attack_tags: ["attack.t1110.001", "attack.credential_access"], falsepositives: [], shadow: false, evidence: { src_ip: "198.51.100.7", count: 25 }, ...over,
  };
}

export async function consoleReq(e: Env, method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return call(e, new Request("https://aegis.test/console/api" + path, { method, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body), headers: { "content-type": "application/json", ...headers } }));
}

export async function cleanDb(): Promise<void> {
  for (const t of ["agent_turns", "audit_log", "ai_reviews", "actions", "anomalies", "incidents", "iocs", "enroll_tokens", "policies", "hosts"]) await env.DB.prepare(`DELETE FROM ${t}`).run();
  await env.DB.prepare("DELETE FROM rules").run();
  await env.DB.prepare("INSERT OR IGNORE INTO policies(host_id, version, body_json, created_by, reason, created_at) VALUES ('default', 1, '{\"thresholds\":{\"native:ssh_bruteforce.count\":10,\"native:ssh_bruteforce.window_s\":60,\"baseline.zscore\":4}}', 'system','seed','1970-01-01T00:00:00.000Z')").run();
  await env.DB.prepare("UPDATE settings SET value='autonomous' WHERE key='autonomy'").run();
}

/** Minimal in-process WorkflowStep: runs callbacks inline; waitForEvent is driven by a test hook (return true = event arrived). */
export class FakeStep {
  names: string[] = [];
  constructor(private onWait: (name: string, type: string) => Promise<boolean>) {}
  async do(name: string, a: unknown, b?: unknown) {
    this.names.push(name);
    const cb = (typeof a === "function" ? a : b) as (ctx: unknown) => Promise<unknown>;
    return cb({ step: { name, count: 1 }, attempt: 1, config: {} });
  }
  async waitForEvent(name: string, o: { type: string }) {
    this.names.push(name);
    if (await this.onWait(name, o.type)) return { payload: {}, timestamp: new Date(), type: o.type };
    throw new Error("timeout");
  }
  async sleep() {}
  async sleepUntil() {}
}
