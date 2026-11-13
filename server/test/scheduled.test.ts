import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { zipSync, strToU8 } from "fflate";
import { dailyDigest, expireStale, fleetCorrelation, handleScheduled, promoteShadowRules } from "../src/scheduled";
import { createAction } from "../src/lib/actions";
import { syncSigmaHQ, upsertSigmaRules } from "../src/sigma/sync";
import { cleanDb, enrollHost, mkAnomaly, mkEnv } from "./helpers";
import type { PolicyBody } from "../src/types";

beforeEach(cleanDb);
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const H = 3600_000;

const sigma = (id: string, level = "medium") => `title: T ${id}\nid: ${id}\nstatus: stable\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  s:\n    Image|endswith: /x\n  condition: s\nlevel: ${level}\ntags:\n  - attack.t1059\n`;

describe("shadow promotion", () => {
  it("promotes only shadow rules >=72h, >=5 hits, 0 FPs; audits as ai", async () => {
    const { env: e } = mkEnv();
    await enrollHost(e);
    const ins = (id: string, status: string, since: string | null, hits: number, fp: number) =>
      env.DB.prepare("INSERT INTO rules(id, pack_id, title, level, yaml, status, created_by, hits_total, fp_total, shadow_since, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(id, "ai", id, "low", "y", status, "ai", hits, fp, since, "t", "t").run();
    await ins("ok", "shadow", iso(73 * H), 5, 0);
    await ins("young", "shadow", iso(10 * H), 50, 0);
    await ins("few-hits", "shadow", iso(100 * H), 4, 0);
    await ins("has-fp", "shadow", iso(100 * H), 50, 1);
    await ins("active", "active", null, 99, 0);
    expect(await promoteShadowRules(e)).toEqual(["ok"]);
    expect((await env.DB.prepare("SELECT id FROM rules WHERE status='active' ORDER BY id").all<{ id: string }>()).results.map((r) => r.id)).toEqual(["active", "ok"]);
    const a = await env.DB.prepare("SELECT actor, detail_json FROM audit_log WHERE event='rule.promoted'").first<{ actor: string; detail_json: string }>();
    expect(a!.actor).toBe("ai");
    expect(await promoteShadowRules(e)).toEqual([]);
  });
});

describe("expire stale", () => {
  it("expires proposals past expires_at and fails old dispatched commands", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    const mk = (state: "proposed" | "approved", exp: string | null) => createAction(e, { id: crypto.randomUUID(), incident_id: null, host_id: h.id, action: "kill_process", params: { pid: Math.floor(Math.random() * 1000) + 2 }, tier: 1, kind: "command", state, proposed_by: "ai", expires_at: exp });
    const old = await mk("proposed", iso(1000));
    const fresh = await mk("proposed", new Date(Date.now() + H).toISOString());
    const disp = await mk("approved", null);
    await env.DB.prepare("UPDATE actions SET state='dispatched', updated_at=? WHERE id=?").bind(iso(2 * H), disp.id).run();
    expect(await expireStale(e)).toEqual({ expired: 1, failed: 1 });
    const st = async (id: string) => (await env.DB.prepare("SELECT state FROM actions WHERE id=?").bind(id).first<{ state: string }>())!.state;
    expect([await st(old.id), await st(fresh.id), await st(disp.id)]).toEqual(["expired", "proposed", "failed"]);
  });
});

describe("fleet correlation", () => {
  it("same IP across hosts escalates the existing incident, records an IOC and audits once", async () => {
    const m = mkEnv();
    const h1 = await enrollHost(m.env, "a");
    const h2 = await enrollHost(m.env, "b");
    const a1 = mkAnomaly({ fingerprint: "1".repeat(64) });
    const a2 = mkAnomaly({ fingerprint: "2".repeat(64) });
    await h1.req(m.env, "POST", "/v1/events", { anomalies: [a1] });
    await h2.req(m.env, "POST", "/v1/events", { anomalies: [a2] });
    const { handleTriageMessage } = await import("../src/queue");
    await handleTriageMessage(m.env, { anomaly_id: a1.id as string });
    await handleTriageMessage(m.env, { anomaly_id: a2.id as string });
    expect(await fleetCorrelation(m.env)).toBe(1);
    const sev = (await env.DB.prepare("SELECT severity FROM incidents").all<{ severity: string }>()).results.map((r) => r.severity);
    expect(sev).toEqual(["high", "high"]);
    expect((await env.DB.prepare("SELECT type, value, watch FROM iocs").first<J>())).toEqual({ type: "ip", value: "198.51.100.7", watch: 0 });
    expect(await fleetCorrelation(m.env)).toBe(0); // deduped
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE event='fleet.correlation'").first<{ n: number }>())!.n).toBe(1);
  });
  it("creates a fleet incident when no incident exists, and ignores private IPs / single hosts", async () => {
    const m = mkEnv();
    const h1 = await enrollHost(m.env, "a");
    const h2 = await enrollHost(m.env, "b");
    const sha = "c".repeat(64);
    await h1.req(m.env, "POST", "/v1/events", { anomalies: [mkAnomaly({ fingerprint: "3".repeat(64), evidence: { sha256: sha, ip: "10.0.0.5" } })] });
    await h2.req(m.env, "POST", "/v1/events", { anomalies: [mkAnomaly({ fingerprint: "4".repeat(64), evidence: { sha256: sha, ip: "10.0.0.5" } })] });
    expect(await fleetCorrelation(m.env)).toBe(1);
    const inc = await env.DB.prepare("SELECT title, severity FROM incidents").first<{ title: string; severity: string }>();
    expect(inc!.title).toContain("sha256");
    expect(inc!.title).toContain("2 hosts");
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM iocs WHERE type='ip'").first<{ n: number }>())!.n).toBe(0);
  });
});

describe("digest and cron dispatch", () => {
  it("writes digests/YYYY-MM-DD.json and an audit entry", async () => {
    const { env: e } = mkEnv();
    await enrollHost(e);
    const key = await dailyDigest(e, new Date("2026-11-12T06:00:00Z"));
    expect(key).toBe("digests/2026-11-12.json");
    const o = JSON.parse(await (await env.EVIDENCE.get(key))!.text());
    expect(o).toHaveProperty("incidents_by_severity");
    expect(o.pending_approvals).toBe(0);
    expect((await env.DB.prepare("SELECT 1 AS x FROM audit_log WHERE event='digest.created'").first())).toBeTruthy();
  });
  it("cron strings route to jobs; a failing job does not abort the others", async () => {
    const { env: e } = mkEnv();
    const fetchBefore = globalThis.fetch;
    globalThis.fetch = (async () => new Response("nope", { status: 500 })) as typeof fetch;
    try {
      await handleScheduled({ cron: "0 6 * * *", scheduledTime: Date.now(), noRetry() {} } as ScheduledController, e);
    } finally {
      globalThis.fetch = fetchBefore;
    }
    expect((await env.DB.prepare("SELECT 1 AS x FROM audit_log WHERE event='digest.created'").first())).toBeTruthy();
    expect((await env.DB.prepare("SELECT 1 AS x FROM audit_log WHERE event='sigma.sync_failed'").first())).toBeTruthy();
  });
});

describe("sigmahq sync", () => {
  it("new rules land in shadow, existing keep status, deprecated skipped, policy carries them, release zip stored in R2", async () => {
    const { env: e } = mkEnv();
    const h = await enrollHost(e);
    const zip = zipSync({
      "sigma-1/rules/linux/a.yml": strToU8(sigma("r-a")),
      "sigma-1/rules/linux/b.yml": strToU8(sigma("r-b", "high")),
      "sigma-1/rules/linux/old.yml": strToU8(sigma("r-old").replace("stable", "deprecated")),
      "sigma-1/rules/linux/bad.yml": strToU8("title: x"),
      "sigma-1/rules/windows/w.yml": strToU8(sigma("r-w")),
    });
    const fake = (async (url: unknown) => {
      const u = String(url);
      if (u.includes("api.github.com")) return Response.json({ tag_name: "r2026-11-01", assets: [{ name: "sigma_all_rules.zip", browser_download_url: "https://dl.example/sigma_all_rules.zip" }] });
      return new Response(zip);
    }) as typeof fetch;
    const r1 = await syncSigmaHQ(e, fake);
    expect(r1).toMatchObject({ tag: "r2026-11-01", added: 2, skipped: 2 });
    const rows = (await env.DB.prepare("SELECT id, status, pack_id, created_by FROM rules ORDER BY id").all<J>()).results;
    expect(rows).toEqual([{ id: "r-a", status: "shadow", pack_id: "sigmahq", created_by: "system" }, { id: "r-b", status: "shadow", pack_id: "sigmahq", created_by: "system" }]);
    expect(await env.EVIDENCE.head("rules/sigmahq/r2026-11-01.zip")).toBeTruthy();
    // second run same tag: no-op
    expect(await syncSigmaHQ(e, fake)).toMatchObject({ unchanged: true });
    // human promotes r-a; a later upsert must not flip it back to shadow
    await env.DB.prepare("UPDATE rules SET status='active' WHERE id='r-a'").run();
    const res = await upsertSigmaRules(e, [{ path: "a.yml", yaml: sigma("r-a", "high") }]);
    expect(res).toMatchObject({ added: 0, updated: 1 });
    expect(await env.DB.prepare("SELECT status, level FROM rules WHERE id='r-a'").first()).toEqual({ status: "active", level: "high" });
    const pol = JSON.parse(atob(((await (await h.req(e, "GET", "/v1/policy")).json()) as { payload: string }).payload)) as { version: number; body: PolicyBody };
    expect(pol.body.rules.map((r) => r.id).sort()).toEqual(["r-a", "r-b"]);
    expect(pol.body.rules.find((r) => r.id === "r-b")!.status).toBe("shadow");
    expect(pol.version).toBeGreaterThan(1);
  });
  it("a sigma rule id that already belongs to a custom pack is not overwritten by sync", async () => {
    const { env: e } = mkEnv();
    await env.DB.prepare("INSERT INTO rules(id, pack_id, title, level, yaml, status, created_by, created_at, updated_at) VALUES ('r-a','custom','mine','low','mine','active','human:x','t','t')").run();
    await upsertSigmaRules(e, [{ path: "a.yml", yaml: sigma("r-a") }]);
    expect(await env.DB.prepare("SELECT title, pack_id FROM rules WHERE id='r-a'").first()).toEqual({ title: "mine", pack_id: "custom" });
  });
});

type J = Record<string, unknown>;
