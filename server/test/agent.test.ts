import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { b64dec, nowIso, sha256Hex } from "../src/lib/util";
import { serverPubkeyB64, verifyEnvelope } from "../src/crypto/sign";
import { cleanDb, call, enrollHost, mkAnomaly, mkEnv, mkToken } from "./helpers";
import type { PolicyBody, SignedEnvelope } from "../src/types";

beforeEach(cleanDb);

const decode = <T>(e: SignedEnvelope): T => JSON.parse(new TextDecoder().decode(b64dec(e.payload))) as T;

describe("enrollment", () => {
  it("one-time token flow returns host_id, server pubkey and a verifiable signed policy", async () => {
    const { env: e } = mkEnv();
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pub = btoa(String.fromCharCode(...new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer)));
    const token = await mkToken();
    const body = JSON.stringify({ token, hostname: "h", os: "linux", arch: "amd64", kernel: "6", agent_version: "1", pubkey: pub });
    const r1 = await call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body }));
    expect(r1.status).toBe(200);
    const j = (await r1.json()) as { host_id: string; server_pubkey: string; policy: SignedEnvelope };
    expect(j.server_pubkey).toBe(await serverPubkeyB64(env.SIGNING_KEY_JWK));
    expect(await verifyEnvelope(b64dec(j.server_pubkey), j.policy)).toBe(true);
    const pol = decode<{ host_id: string; version: number; body: PolicyBody }>(j.policy);
    expect(pol).toMatchObject({ host_id: j.host_id, version: 1 });
    expect(pol.body.thresholds["native:ssh_bruteforce.count"]).toBe(10);
    expect(pol.body.server_endpoints).toContain("aegis.test");
    // token stored hashed, marked used
    const row = await env.DB.prepare("SELECT * FROM enroll_tokens WHERE token_hash=?").bind(await sha256Hex(token)).first<{ used_at: string; host_id: string }>();
    expect(row?.host_id).toBe(j.host_id);
    expect(await env.DB.prepare("SELECT 1 AS x FROM enroll_tokens WHERE token_hash=?").bind(token).first()).toBeNull();
    // replay fails
    const r2 = await call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body }));
    expect(r2.status).toBe(401);
  });
  it("rejects expired, unknown tokens and bad pubkeys", async () => {
    const { env: e } = mkEnv();
    const good = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
    const mk = (token: string, pubkey = good) => call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body: JSON.stringify({ token, hostname: "h", pubkey }) }));
    expect((await mk("nope-nope-nope")).status).toBe(401);
    const expired = await mkToken(-1000);
    expect((await mk(expired)).status).toBe(401);
    const t = await mkToken();
    expect((await mk(t, btoa("short-key-short-key-short-key-short-key"))).status).toBe(400);
    expect((await call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body: "{" }))).status).toBe(400);
    // a bad-pubkey attempt must not burn the token
    expect((await mk(t)).status).toBe(200);
  });
});

describe("agent auth", () => {
  it("accepts good signature; rejects bad sig, skew, unknown host, missing headers, tampered body", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    expect((await h.req(e, "GET", "/v1/policy")).status).toBe(200);
    expect((await h.req(e, "GET", "/v1/policy", undefined, { badSig: true })).status).toBe(401);
    const now = Math.floor(Date.now() / 1000);
    expect((await h.req(e, "GET", "/v1/policy", undefined, { ts: now - 301 })).status).toBe(401);
    expect((await h.req(e, "GET", "/v1/policy", undefined, { ts: now + 301 })).status).toBe(401);
    expect((await h.req(e, "GET", "/v1/policy", undefined, { ts: now - 299 })).status).toBe(200);
    expect((await h.req(e, "GET", "/v1/policy", undefined, { headers: { "X-Aegis-Host": crypto.randomUUID() } })).status).toBe(401);
    expect((await call(e, new Request("https://aegis.test/v1/policy"))).status).toBe(401);
    // signature bound to path and body
    const res = await call(e, new Request("https://aegis.test/v1/heartbeat", { method: "POST", body: "{}", headers: { "X-Aegis-Host": h.id, "X-Aegis-Ts": String(now), "X-Aegis-Sig": "AAAA" } }));
    expect(res.status).toBe(401);
  });
  it("one host cannot act as another", async () => {
    const { env: e } = mkEnv();
    const a = await enrollHost(e, "a");
    const b = await enrollHost(e, "b");
    const res = await a.req(e, "GET", "/v1/policy", undefined, { headers: { "X-Aegis-Host": b.id } });
    expect(res.status).toBe(401);
  });
});

describe("ingest", () => {
  it("stores anomalies, enqueues non-shadow ids, bumps rule hits, large evidence to R2, dedupes retries", async () => {
    const { env: e, cap } = mkEnv();
    const h = await enrollHost(e);
    await env.DB.prepare("INSERT INTO rules(id, pack_id, title, level, yaml, status, created_by, shadow_since, created_at, updated_at) VALUES ('shadow-rule','custom','t','low','y','shadow','test',?,?,?)").bind(nowIso(), nowIso(), nowIso()).run();
    const normal = mkAnomaly();
    const big = mkAnomaly({ id: crypto.randomUUID(), evidence: { blob: "x".repeat(20000) } });
    const shadow = mkAnomaly({ id: crypto.randomUUID(), rule_id: "shadow-rule", rule_source: "sigma", shadow: true });
    const shadow2 = mkAnomaly({ id: crypto.randomUUID(), rule_id: "shadow-rule", rule_source: "sigma", shadow: true });
    const invalid = { id: "not-a-uuid" };
    const res = await h.req(e, "POST", "/v1/events", { anomalies: [normal, big, shadow, shadow2, invalid] });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ accepted: 4, rejected: 1 });
    expect(cap.queued.map((q) => q.anomaly_id).sort()).toEqual([normal.id, big.id].sort());
    const row = await env.DB.prepare("SELECT * FROM anomalies WHERE id=?").bind(big.id).first<{ evidence_json: string | null; evidence_r2_key: string | null; host_id: string }>();
    expect(row?.evidence_json).toBeNull();
    expect(row?.evidence_r2_key).toBe(`evidence/${h.id}/${big.id}.json`);
    expect(row?.host_id).toBe(h.id);
    const obj = await env.EVIDENCE.get(row!.evidence_r2_key!);
    expect(JSON.parse(await obj!.text()).blob.length).toBe(20000);
    const small = await env.DB.prepare("SELECT evidence_json, evidence_r2_key FROM anomalies WHERE id=?").bind(normal.id).first<{ evidence_json: string; evidence_r2_key: string | null }>();
    expect(JSON.parse(small!.evidence_json).count).toBe(25);
    expect(small!.evidence_r2_key).toBeNull();
    expect((await env.DB.prepare("SELECT hits_total FROM rules WHERE id='shadow-rule'").first<{ hits_total: number }>())!.hits_total).toBe(2);
    // retry: nothing new queued, hits unchanged
    cap.queued.length = 0;
    await h.req(e, "POST", "/v1/events", { anomalies: [normal, shadow] });
    expect(cap.queued).toHaveLength(0);
    expect((await env.DB.prepare("SELECT hits_total FROM rules WHERE id='shadow-rule'").first<{ hits_total: number }>())!.hits_total).toBe(2);
    expect((await env.DB.prepare("SELECT last_seen FROM hosts WHERE id=?").bind(h.id).first<{ last_seen: string }>())!.last_seen).toBeTruthy();
  });
  it("rejects bad bodies and >500 batches", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    expect((await h.req(e, "POST", "/v1/events", "not json")).status).toBe(400);
    expect((await h.req(e, "POST", "/v1/events", { anomalies: Array.from({ length: 501 }, () => ({})) })).status).toBe(400);
  });
});

describe("heartbeat, policy, commands, results", () => {
  it("heartbeat updates host and returns latest policy_version; rule errors degrade", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    const res = await h.req(e, "POST", "/v1/heartbeat", { agent_version: "0.2.0", policy_version: 1, uptime_s: 10, stats: { events_per_min: 5, anomalies_per_min: 0, rules_loaded: 3, buffer_events: 0 }, rule_errors: [{ rule_id: "r", error: "bad" }], ws_connected: false });
    expect(await res.json()).toEqual({ policy_version: 1 });
    const row = await env.DB.prepare("SELECT * FROM hosts WHERE id=?").bind(h.id).first<{ status: string; agent_version: string; stats_json: string }>();
    expect(row).toMatchObject({ status: "degraded", agent_version: "0.2.0" });
    expect(JSON.parse(row!.stats_json).rules_loaded).toBe(3);
  });
  it("command dispatch -> poll -> result -> state, and cross-host result is refused", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    const other = await enrollHost(e, "other");
    const created = await call(e, new Request("https://aegis.test/console/api/actions", { method: "POST", body: JSON.stringify({ host_id: h.id, action: "collect_evidence", params: { kind: "netconns" } }) }));
    expect(created.status).toBe(200);
    const action = (await created.json()) as { id: string; state: string };
    expect(action.state).toBe("dispatched");
    const polled = (await (await h.req(e, "GET", "/v1/commands")).json()) as { commands: SignedEnvelope[] };
    expect(polled.commands).toHaveLength(1);
    expect(await verifyEnvelope(b64dec(await serverPubkeyB64(env.SIGNING_KEY_JWK)), polled.commands[0]!)).toBe(true);
    const cmd = decode<{ id: string; host_id: string; action: string; expires_at: string }>(polled.commands[0]!);
    expect(cmd).toMatchObject({ id: action.id, host_id: h.id, action: "collect_evidence" });
    expect(Date.parse(cmd.expires_at)).toBeGreaterThan(Date.now());
    expect((await other.req(e, "POST", "/v1/results", { command_id: action.id, status: "succeeded", result: {} })).status).toBe(404);
    expect((await h.req(e, "POST", "/v1/results", { command_id: action.id, status: "succeeded", result: { data: { conns: [] } } })).status).toBe(200);
    const row = await env.DB.prepare("SELECT state, result_json FROM actions WHERE id=?").bind(action.id).first<{ state: string; result_json: string }>();
    expect(row!.state).toBe("succeeded");
    expect(JSON.parse(row!.result_json)).toEqual({ data: { conns: [] } });
    expect(((await (await h.req(e, "GET", "/v1/commands")).json()) as { commands: unknown[] }).commands).toHaveLength(0);
    // duplicate result is idempotent
    expect((await h.req(e, "POST", "/v1/results", { command_id: action.id, status: "failed", error: "x" })).status).toBe(200);
    expect((await env.DB.prepare("SELECT state FROM actions WHERE id=?").bind(action.id).first<{ state: string }>())!.state).toBe("succeeded");
  });
  it("websocket receives pushed commands and policy_updated", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    const res = await h.req(e, "GET", "/v1/ws", undefined, { headers: { Upgrade: "websocket" } });
    expect(res.status).toBe(101);
    const ws = res.webSocket!;
    ws.accept();
    const msgs: { type: string }[] = [];
    ws.addEventListener("message", (m) => { msgs.push(JSON.parse(m.data as string)); });
    const created = await call(e, new Request("https://aegis.test/console/api/actions", { method: "POST", body: JSON.stringify({ host_id: h.id, action: "raise_log_level", params: { ttl_seconds: 600 } }) }));
    expect(created.status).toBe(200);
    await call(e, new Request(`https://aegis.test/console/api/policies/${h.id}`, { method: "POST", body: JSON.stringify({ body: { log_level: "debug" }, reason: "t" }) }));
    for (let i = 0; i < 20 && msgs.length < 2; i++) await new Promise((r) => setTimeout(r, 50));
    expect(msgs.map((m) => m.type)).toEqual(["command", "policy_updated"]);
    ws.close();
  });
  it("ws without upgrade header is refused", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    expect((await h.req(e, "GET", "/v1/ws")).status).toBe(426);
  });
});
