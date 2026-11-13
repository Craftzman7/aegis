import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { handleTriageMessage } from "../src/queue";
import { cleanDb, call, consoleReq, enrollHost, mkAnomaly, mkEnv } from "./helpers";
import type { IncidentRow } from "../src/types";

beforeEach(cleanDb);
type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe("console auth", () => {
  it("DEV_MODE=true gives dev@local", async () => {
    const { env: e } = mkEnv();
    expect(await (await consoleReq(e, "GET", "/me")).json()).toEqual({ email: "dev@local" });
  });
  it("without DEV_MODE, requests need a valid Access JWT (fail closed)", async () => {
    const { env: e } = mkEnv(undefined, { DEV_MODE: "false", ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud" });
    expect((await consoleReq(e, "GET", "/me")).status).toBe(401);
    expect((await consoleReq(e, "GET", "/me", undefined, { "Cf-Access-Jwt-Assertion": "a.b.c" })).status).toBe(401);
    expect((await consoleReq(e, "GET", "/incidents", undefined, { "Cf-Access-Jwt-Assertion": "garbage" })).status).toBe(401);
    const unconfigured = mkEnv(undefined, { DEV_MODE: "false", ACCESS_TEAM_DOMAIN: "", ACCESS_AUD: "" });
    expect((await consoleReq(unconfigured.env, "GET", "/me")).status).toBe(503);
  });
  it("live feed requires websocket and streams published events", async () => {
    const { env: e } = mkEnv();
    expect((await call(e, new Request("https://aegis.test/console/live"))).status).toBe(426);
    const res = await call(e, new Request("https://aegis.test/console/live", { headers: { Upgrade: "websocket" } }));
    expect(res.status).toBe(101);
    const ws = res.webSocket!;
    ws.accept();
    const msgs: J[] = [];
    ws.addEventListener("message", (m) => { msgs.push(JSON.parse(m.data as string)); });
    await consoleReq(e, "POST", "/settings/autonomy", { mode: "propose_only" });
    for (let i = 0; i < 30 && !msgs.some((m) => m.type === "audit"); i++) await new Promise((r) => setTimeout(r, 50));
    const a = msgs.find((m) => m.type === "audit")!;
    expect(a.data.event).toBe("autonomy.global");
    expect(a.data.detail).toEqual({ mode: "propose_only" });
    expect(typeof a.ts).toBe("string");
    ws.close();
  });
});

async function incidentFixture() {
  const m = mkEnv();
  const host = await enrollHost(m.env);
  const a = mkAnomaly({ severity: "high" });
  await host.req(m.env, "POST", "/v1/events", { anomalies: [a] });
  await handleTriageMessage(m.env, { anomaly_id: a.id as string });
  const inc = (await env.DB.prepare("SELECT * FROM incidents").first<IncidentRow>())!;
  return { ...m, host, a, inc };
}

describe("console API", () => {
  it("overview shape", async () => {
    const f = await incidentFixture();
    const o = (await (await consoleReq(f.env, "GET", "/overview")).json()) as J;
    expect(o.hosts).toEqual({ total: 1, online: 1, offline: 0, isolated: 0 });
    expect(o.incidents_by_severity).toMatchObject({ high: 1, critical: 0 });
    expect(o.anomalies_24h_hourly).toHaveLength(25);
    expect(Date.parse(o.anomalies_24h_hourly[0].hour)).not.toBeNaN();
    expect(o.anomalies_24h_hourly.reduce((s: number, b: J) => s + b.count, 0)).toBe(1);
    expect(o).toMatchObject({ pending_approvals: 0, ai_actions_24h: 0, autonomy: "autonomous" });
  });
  it("hosts, incidents and details parse *_json columns", async () => {
    const f = await incidentFixture();
    const hosts = (await (await consoleReq(f.env, "GET", "/hosts")).json()) as J[];
    expect(hosts[0]).toMatchObject({ hostname: "web-1", online: true });
    const hd = (await (await consoleReq(f.env, "GET", `/hosts/${f.host.id}`)).json()) as J;
    expect(hd.anomalies[0].attack_tags).toContain("attack.t1110.001");
    expect(hd.anomalies[0].evidence).toEqual({ src_ip: "198.51.100.7", count: 25 });
    expect(hd.policy.version).toBe(1);
    const list = (await (await consoleReq(f.env, "GET", "/incidents?severity=high")).json()) as J[];
    expect(list).toHaveLength(1);
    expect(list[0].attack_tags).toBeInstanceOf(Array);
    expect(((await (await consoleReq(f.env, "GET", "/incidents?status=closed_tp")).json()) as J[]).length).toBe(0);
    const d = (await (await consoleReq(f.env, "GET", `/incidents/${f.inc.id}`)).json()) as J;
    expect(Object.keys(d).sort()).toEqual(["actions", "anomalies", "audit", "incident", "reviews", "turns"]);
    expect((await consoleReq(f.env, "GET", "/incidents/nope")).status).toBe(404);
  });
  it("manual actions go through gate bounds; tier ignored; audited", async () => {
    const f = await incidentFixture();
    const r = await consoleReq(f.env, "POST", "/actions", { host_id: f.host.id, action: "kill_process", params: { pid: 4242 }, incident_id: f.inc.id });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ state: "dispatched", proposed_by: "human:dev@local", tier: 1 });
    expect((await consoleReq(f.env, "POST", "/actions", { host_id: f.host.id, action: "block_ip", params: { ip: "127.0.0.1" } })).status).toBe(422);
    expect((await consoleReq(f.env, "POST", "/actions", { host_id: f.host.id, action: "disable_user", params: { username: "root" } })).status).toBe(422);
    expect((await consoleReq(f.env, "POST", "/actions", { host_id: "nope", action: "kill_process", params: { pid: 3 } })).status).toBe(404);
    const aud = (await (await consoleReq(f.env, "GET", "/audit?actor=human&limit=50")).json()) as J[];
    expect(aud.some((x) => x.event === "gate.rejected")).toBe(true);
    expect(aud.every((x) => x.actor.startsWith("human"))).toBe(true);
  });
  it("approve revalidates modified params, dispatches, and rollback requires succeeded+token", async () => {
    const f = await incidentFixture();
    const prop = await (await import("../src/lib/actions")).createAction(f.env, { id: crypto.randomUUID(), incident_id: f.inc.id, host_id: f.host.id, action: "block_ip", params: { ip: "198.51.100.7", ttl_seconds: 3600 }, tier: 1, kind: "command", state: "proposed", proposed_by: "ai", rationale: "brute force" });
    const approvals = (await (await consoleReq(f.env, "GET", "/approvals")).json()) as J[];
    expect(approvals[0]).toMatchObject({ id: prop.id, host: { id: f.host.id }, incident: { id: f.inc.id } });
    expect((await consoleReq(f.env, "POST", `/actions/${prop.id}/approve`, { params: { ip: "127.0.0.1" } })).status).toBe(422);
    expect((await consoleReq(f.env, "POST", `/actions/${prop.id}/rollback`)).status).toBe(409);
    const ok = await consoleReq(f.env, "POST", `/actions/${prop.id}/approve`, { ttl_seconds: 600 });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ state: "dispatched", approved_by: "human:dev@local", params: { ip: "198.51.100.7", ttl_seconds: 600 } });
    expect(f.cap.events.some((x) => x.type === "approval")).toBe(true);
    expect((await consoleReq(f.env, "POST", `/actions/${prop.id}/approve`, {})).status).toBe(409);
    await f.host.req(f.env, "POST", "/v1/results", { command_id: prop.id, status: "succeeded", result: {}, rollback_token: "rb-token-123" });
    const rb = await consoleReq(f.env, "POST", `/actions/${prop.id}/rollback`);
    expect(rb.status).toBe(200);
    const rbj = (await rb.json()) as J;
    expect(rbj).toMatchObject({ action: "rollback", params: { rollback_token: "rb-token-123" }, rollback_of: prop.id, state: "dispatched" });
    expect((await consoleReq(f.env, "POST", `/actions/${prop.id}/rollback`)).status).toBe(409);
    await f.host.req(f.env, "POST", "/v1/results", { command_id: rbj.id, status: "succeeded", result: {} });
    expect((await env.DB.prepare("SELECT state FROM actions WHERE id=?").bind(prop.id).first<{ state: string }>())!.state).toBe("rolled_back");
  });
  it("isolate_host result flips host status; rollback restores it", async () => {
    const f = await incidentFixture();
    const r = (await (await consoleReq(f.env, "POST", "/actions", { host_id: f.host.id, action: "isolate_host", params: { ttl_seconds: 600 } })).json()) as J;
    await f.host.req(f.env, "POST", "/v1/results", { command_id: r.id, status: "succeeded", result: {}, rollback_token: "iso-token-1" });
    expect((await env.DB.prepare("SELECT status FROM hosts WHERE id=?").bind(f.host.id).first<{ status: string }>())!.status).toBe("isolated");
    const rb = (await (await consoleReq(f.env, "POST", `/actions/${r.id}/rollback`)).json()) as J;
    await f.host.req(f.env, "POST", "/v1/results", { command_id: rb.id, status: "succeeded", result: {} });
    expect((await env.DB.prepare("SELECT status FROM hosts WHERE id=?").bind(f.host.id).first<{ status: string }>())!.status).toBe("ok");
  });
  it("verdict override labels incident, updates rule stats, embeds to memory, terminates workflow", async () => {
    const f = await incidentFixture();
    await env.DB.prepare("INSERT INTO rules(id, pack_id, title, level, yaml, status, created_by, created_at, updated_at) VALUES ('native:ssh_bruteforce','custom','t','low','y','active','x',?,?)").bind("t", "t").run();
    await env.DB.prepare("INSERT INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES ('i1','ip','198.51.100.7','ai',?,0,'t')").bind(f.inc.id).run();
    const r = await consoleReq(f.env, "POST", `/incidents/${f.inc.id}/verdict`, { verdict: "false_positive", note: "pentest" });
    expect(r.status).toBe(200);
    const inc = (await env.DB.prepare("SELECT * FROM incidents WHERE id=?").bind(f.inc.id).first<IncidentRow>())!;
    expect(inc).toMatchObject({ verdict: "false_positive", status: "closed_benign", analyst_note: "pentest" });
    expect(inc.closed_at).toBeTruthy();
    expect((await env.DB.prepare("SELECT fp_total, tp_total FROM rules WHERE id='native:ssh_bruteforce'").first<J>())).toEqual({ fp_total: 1, tp_total: 0 });
    expect(f.cap.events.some((x) => x.type === "terminate")).toBe(true);
    for (let i = 0; i < 20 && f.cap.vectors.length === 0; i++) await new Promise((r2) => setTimeout(r2, 25));
    expect(f.cap.vectors).toHaveLength(1);
    expect((f.cap.vectors[0] as J).metadata.label).toBe("false_positive");
    expect((await env.DB.prepare("SELECT watch FROM iocs WHERE id='i1'").first<{ watch: number }>())!.watch).toBe(0);
  });
  it("true_positive verdict turns on IOC watch and bumps policy versions", async () => {
    const f = await incidentFixture();
    await env.DB.prepare("INSERT INTO iocs(id, type, value, source, incident_id, watch, first_seen) VALUES ('i1','ip','198.51.100.7','ai',?,0,'t')").bind(f.inc.id).run();
    await consoleReq(f.env, "POST", `/incidents/${f.inc.id}/verdict`, { verdict: "true_positive", note: "" });
    expect((await env.DB.prepare("SELECT watch FROM iocs WHERE id='i1'").first<{ watch: number }>())!.watch).toBe(1);
    for (let i = 0; i < 40; i++) {
      const v = (await env.DB.prepare("SELECT policy_version FROM hosts WHERE id=?").bind(f.host.id).first<{ policy_version: number }>())!.policy_version;
      if (v > 1) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const pol = (await (await f.host.req(f.env, "GET", "/v1/policy")).json()) as { payload: string };
    const body = JSON.parse(atob(pol.payload));
    expect(body.version).toBeGreaterThan(1);
    expect(body.body.iocs).toEqual([{ type: "ip", value: "198.51.100.7" }]);
  });
  it("ask is read-only and logs a review", async () => {
    const m = mkEnv(() => ({ response: "It looks like a scanner." }));
    const host = await enrollHost(m.env);
    const a = mkAnomaly();
    await host.req(m.env, "POST", "/v1/events", { anomalies: [a] });
    await handleTriageMessage(m.env, { anomaly_id: a.id as string });
    const inc = (await env.DB.prepare("SELECT id FROM incidents").first<{ id: string }>())!;
    const r = await consoleReq(m.env, "POST", `/incidents/${inc.id}/ask`, { question: "Is this a scanner?" });
    expect(await r.json()).toEqual({ answer: "It looks like a scanner." });
    const chat = m.cap.aiCalls.filter((c) => !c.model.includes("bge"));
    expect(chat[0]!.input.response_format).toBeUndefined();
    expect((chat[0]!.input.messages as { content: string }[])[0]!.content).toContain("READ-ONLY");
    expect((await env.DB.prepare("SELECT step FROM ai_reviews").first<{ step: string }>())!.step).toBe("ask");
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM actions").first<{ n: number }>())!.n).toBe(0);
  });
  it("audit pagination with before/limit", async () => {
    const f = await incidentFixture();
    for (let i = 0; i < 5; i++) await consoleReq(f.env, "POST", "/settings/autonomy", { mode: "autonomous" });
    const p1 = (await (await consoleReq(f.env, "GET", "/audit?limit=3")).json()) as J[];
    expect(p1).toHaveLength(3);
    const p2 = (await (await consoleReq(f.env, "GET", `/audit?limit=3&before=${p1[2]!.id}`)).json()) as J[];
    expect(p2[0]!.id).toBeLessThan(p1[2]!.id);
    expect(((await (await consoleReq(f.env, "GET", "/audit?event=autonomy")).json()) as J[]).every((x) => x.event.startsWith("autonomy"))).toBe(true);
  });
  it("autonomy per host accepts null (inherit)", async () => {
    const f = await incidentFixture();
    await consoleReq(f.env, "POST", `/hosts/${f.host.id}/autonomy`, { mode: "paused" });
    expect((await env.DB.prepare("SELECT autonomy FROM hosts WHERE id=?").bind(f.host.id).first<{ autonomy: string }>())!.autonomy).toBe("paused");
    expect((await consoleReq(f.env, "POST", `/hosts/${f.host.id}/autonomy`, { mode: null })).status).toBe(200);
    expect((await env.DB.prepare("SELECT autonomy FROM hosts WHERE id=?").bind(f.host.id).first<{ autonomy: string | null }>())!.autonomy).toBeNull();
    expect((await consoleReq(f.env, "POST", `/hosts/${f.host.id}/autonomy`, { mode: "yolo" })).status).toBe(400);
  });
  it("enroll token endpoint returns a usable one-time token", async () => {
    const { env: e } = mkEnv();
    const t = (await (await consoleReq(e, "POST", "/enroll-tokens", { ttl_hours: 1 })).json()) as J;
    expect(t.token).toMatch(/^aegis_/);
    const pub = btoa(String.fromCharCode(...new Uint8Array(32).fill(3)));
    const r = await call(e, new Request("https://aegis.test/v1/enroll", { method: "POST", body: JSON.stringify({ token: t.token, hostname: "x", pubkey: pub }) }));
    expect(r.status).toBe(200);
  });
});

describe("rules, policies, coverage", () => {
  const RULE = (id: string, tags = "") => `title: R ${id}\nid: ${id}\nlogsource:\n  product: linux\ndetection:\n  s:\n    Image|endswith: /x\n  condition: s\nlevel: medium\n${tags}`;
  it("lint, create (shadow), status change bumps policy, test (draft and by id), coverage", async () => {
    const f = await incidentFixture();
    expect(await (await consoleReq(f.env, "POST", "/rules/lint", { yaml: "title: x" })).json()).toMatchObject({ ok: false });
    expect(await (await consoleReq(f.env, "POST", "/rules/lint", { yaml: RULE("lint-1") })).json()).toEqual({ ok: true, errors: [] });
    expect((await consoleReq(f.env, "POST", "/rules", { yaml: "bad", status: "shadow" })).status).toBe(422);
    const created = (await (await consoleReq(f.env, "POST", "/rules", { yaml: RULE("custom-1", "tags:\n  - attack.t1059.004\n"), status: "shadow" })).json()) as J;
    expect(created).toMatchObject({ id: "custom-1", status: "shadow", pack_id: "custom", attack_tags: ["attack.t1059.004"] });
    expect(created.shadow_since).toBeTruthy();
    const st = await consoleReq(f.env, "POST", "/rules/custom-1/status", { status: "active" });
    expect(await st.json()).toMatchObject({ status: "active", shadow_since: null });
    expect((await consoleReq(f.env, "POST", "/rules/missing/status", { status: "active" })).status).toBe(404);
    const cov = (await (await consoleReq(f.env, "GET", "/coverage")).json()) as J;
    expect(cov.techniques).toEqual(expect.arrayContaining([{ id: "T1059.004", rules: 1, hits_30d: 0 }, { id: "T1110.001", rules: 0, hits_30d: 1 }]));
    // rule tests dispatch a test_rule command and (since the agent never answers) report the dispatched state after the wait window
    const draft = consoleReq(f.env, "POST", "/rules/draft/test", { host_id: f.host.id, yaml: RULE("draft-1") });
    const pending = (await Promise.race([draft, new Promise<null>((r) => setTimeout(() => r(null), 300))]));
    expect(pending).toBeNull(); // still waiting for the agent: the endpoint polls
    const cmds = (await (await f.host.req(f.env, "GET", "/v1/commands")).json()) as { commands: unknown[] };
    expect(cmds.commands.length).toBeGreaterThan(0);
    const row = (await env.DB.prepare("SELECT id FROM actions WHERE action='test_rule'").first<{ id: string }>())!;
    await f.host.req(f.env, "POST", "/v1/results", { command_id: row.id, status: "succeeded", result: { matches: 2, samples: [] } });
    const res = (await (await draft)).clone();
    expect(await res.json()).toMatchObject({ state: "succeeded", result: { matches: 2 } });
    expect((await consoleReq(f.env, "POST", "/rules/draft/test", { host_id: f.host.id, yaml: "bad" })).status).toBe(422);
  }, 30000);
  it("sigmahq list omits yaml but /rules/:id has it", async () => {
    const { env: e } = mkEnv();
    await env.DB.prepare("INSERT INTO rules(id, pack_id, title, level, yaml, status, created_by, created_at, updated_at) VALUES ('s1','sigmahq','t','low','YAML','shadow','system','t','t')").run();
    const l = (await (await consoleReq(e, "GET", "/rules")).json()) as J[];
    expect(l[0]!.yaml).toBeUndefined();
    expect(l[0]!.has_yaml).toBe(true);
    expect(((await (await consoleReq(e, "GET", "/rules/s1")).json()) as J).yaml).toBe("YAML");
  });
  it("policy history and manual edits create versions", async () => {
    const f = await incidentFixture();
    const r = (await (await consoleReq(f.env, "POST", `/policies/${f.host.id}`, { body: { thresholds: { "native:ssh_bruteforce.count": 25 } }, reason: "noisy" })).json()) as J;
    expect(r.version).toBe(2);
    const hist = (await (await consoleReq(f.env, "GET", `/policies/${f.host.id}`)).json()) as J[];
    expect(hist.map((h) => h.version)).toEqual([2, 1]);
    expect(hist[0]).toMatchObject({ created_by: "human:dev@local", reason: "noisy", body: { thresholds: { "native:ssh_bruteforce.count": 25 } } });
    const pol = JSON.parse(atob(((await (await f.host.req(f.env, "GET", "/v1/policy")).json()) as J).payload));
    expect(pol.version).toBe(2);
    expect(pol.body.thresholds["native:ssh_bruteforce.count"]).toBe(25);
    expect(pol.body.thresholds["baseline.zscore"]).toBe(4); // default merged in
    expect((await consoleReq(f.env, "POST", `/policies/${f.host.id}`, { body: { evil: 1 }, reason: "x" })).status).toBe(400);
    expect((await consoleReq(f.env, "POST", "/policies/nohost", { body: {}, reason: "x" })).status).toBe(404);
  });
  it("AI policy actions: threshold respects gate; suppression and watch apply as new versions", async () => {
    const f = await incidentFixture();
    const { applyPolicyAction } = await import("../src/policy/service");
    await applyPolicyAction(f.env, f.host.id, "add_watch", { kind: "path", target: "/etc/cron.d" }, "ai", "r");
    await applyPolicyAction(f.env, f.host.id, "suppress", { fingerprint: "a".repeat(64), ttl_seconds: 3600, reason: "scanner" }, "ai", "r");
    const pol = JSON.parse(atob(((await (await f.host.req(f.env, "GET", "/v1/policy")).json()) as J).payload));
    expect(pol.body.watches).toEqual([{ kind: "path", target: "/etc/cron.d" }]);
    expect(pol.body.suppressions[0]).toMatchObject({ fingerprint: "a".repeat(64), reason: "scanner" });
    expect(pol.version).toBe(3);
  });
});

describe("export / import", () => {
  it("OCSF detection finding", async () => {
    const f = await incidentFixture();
    const o = (await (await consoleReq(f.env, "GET", `/export/incidents/${f.inc.id}.ocsf.json`)).json()) as J;
    expect(o).toMatchObject({ class_uid: 2004, class_name: "Detection Finding", category_uid: 2, severity_id: 4, device: { hostname: "web-1" } });
    expect(o.finding_info.attacks[0].technique.uid).toBe("T1110.001");
    expect(o.finding_info.related_events).toHaveLength(1);
    expect((await consoleReq(f.env, "GET", "/export/incidents/nope.ocsf.json")).status).toBe(404);
  });
  it("IOC import (CSV and STIX), STIX export, and agents receive watched IOCs", async () => {
    const f = await incidentFixture();
    const sha = "a".repeat(64);
    const csv = `type,value\nip,203.0.113.50\nsha256,${sha.toUpperCase()}\ndomain,Evil.Example.com\nip,not-an-ip\n# c\n`;
    const r = (await (await call(f.env, new Request("https://aegis.test/console/api/iocs/import?name=feed1", { method: "POST", body: csv, headers: { "content-type": "text/csv" } }))).json()) as J;
    expect(r).toMatchObject({ imported: 3, skipped: 0 });
    expect(r.errors).toHaveLength(1);
    const bundle = { type: "bundle", id: "bundle--1", objects: [{ type: "indicator", id: "indicator--1", pattern: "[ipv4-addr:value = '203.0.113.51'] OR [file:hashes.'SHA-256' = '" + "b".repeat(64) + "']", pattern_type: "stix" }, { type: "malware", id: "m--1" }] };
    const r2 = (await (await call(f.env, new Request("https://aegis.test/console/api/iocs/import", { method: "POST", body: JSON.stringify(bundle), headers: { "content-type": "application/json" } }))).json()) as J;
    expect(r2.imported).toBe(2);
    const again = (await (await call(f.env, new Request("https://aegis.test/console/api/iocs/import", { method: "POST", body: csv, headers: { "content-type": "text/csv" } }))).json()) as J;
    expect(again).toMatchObject({ imported: 0, skipped: 3 });
    const stix = (await (await consoleReq(f.env, "GET", "/export/iocs.stix.json")).json()) as J;
    expect(stix.type).toBe("bundle");
    expect(stix.objects).toHaveLength(5);
    expect(stix.objects.map((o: J) => o.pattern)).toEqual(expect.arrayContaining(["[ipv4-addr:value = '203.0.113.50']", `[file:hashes.'SHA-256' = '${sha}']`, "[domain-name:value = 'evil.example.com']"]));
    for (let i = 0; i < 40; i++) {
      const v = (await env.DB.prepare("SELECT policy_version FROM hosts").first<{ policy_version: number }>())!.policy_version;
      if (v > 1) break;
      await new Promise((x) => setTimeout(x, 25));
    }
    const pol = JSON.parse(atob(((await (await f.host.req(f.env, "GET", "/v1/policy")).json()) as J).payload));
    expect(pol.body.iocs).toHaveLength(5);
  });
  it("evidence endpoint only serves evidence/ and digests/ keys", async () => {
    const { env: e } = mkEnv();
    await env.EVIDENCE.put("evidence/h/a.json", '{"x":1}');
    await env.EVIDENCE.put("rules/sigmahq/x.zip", "zip");
    expect(await (await consoleReq(e, "GET", "/evidence?key=evidence/h/a.json")).json()).toEqual({ x: 1 });
    expect((await consoleReq(e, "GET", "/evidence?key=rules/sigmahq/x.zip")).status).toBe(400);
    expect((await consoleReq(e, "GET", "/evidence?key=evidence/../rules/x")).status).toBe(400);
    expect((await consoleReq(e, "GET", "/evidence?key=evidence/none.json")).status).toBe(404);
  });
});

describe("installer and releases", () => {
  it("serves install.sh with the request origin and release binaries from R2", async () => {
    const { env: e } = mkEnv();
    const sh = await (await call(e, new Request("https://soc.example.dev/install.sh"))).text();
    expect(sh).toContain('SERVER="https://soc.example.dev"');
    expect(sh).toContain("--token");
    expect(sh).toContain('enroll --server "$SERVER" --token "$TOKEN"');
    expect(sh).toContain("systemctl enable --now aegis-agent");
    expect(sh).toContain("/etc/aegis/agent.yaml");
    expect((await call(e, new Request("https://aegis.test/releases/agent/latest/aegis-agent-linux-amd64"))).status).toBe(404);
    await env.EVIDENCE.put("releases/agent/latest/aegis-agent-linux-arm64", "BIN");
    const r = await call(e, new Request("https://aegis.test/releases/agent/latest/aegis-agent-linux-arm64"));
    expect(await r.text()).toBe("BIN");
    expect((await call(e, new Request("https://aegis.test/releases/agent/latest/other"))).status).toBe(404);
  });
});
