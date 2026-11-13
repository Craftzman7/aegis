import { signEnvelope } from "../crypto/sign";
import { audit } from "../lib/audit";
import { publish } from "../lib/fleet";
import { hostStub } from "../lib/stubs";
import { nowIso, safeJson } from "../lib/util";
import type { HostRow, PolicyBody, SignedEnvelope, StoredPolicyBody } from "../types";

export const BUILTIN_DEFAULT: Required<StoredPolicyBody> = {
  log_level: "info",
  thresholds: { "native:ssh_bruteforce.count": 10, "native:ssh_bruteforce.window_s": 60, "baseline.zscore": 4 },
  watches: [],
  suppressions: [],
};

/**
 * Public hostnames of this deployment, remembered from the first agent request we see
 * (stored in settings.server_endpoints) so isolation always has an allow-list, even in cron/workflow context.
 */
export async function getServerEndpoints(env: Env): Promise<string[]> {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key='server_endpoints'").first<{ value: string }>();
  return safeJson<string[]>(r?.value, []);
}

export async function rememberServerEndpoint(env: Env, requestUrl: string): Promise<void> {
  let host: string;
  try {
    host = new URL(requestUrl).hostname;
  } catch {
    return;
  }
  if (!host) return;
  const cur = await getServerEndpoints(env);
  if (cur.includes(host)) return;
  const next = [...cur, host].slice(-5);
  await env.DB.prepare("INSERT INTO settings(key,value) VALUES('server_endpoints',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(JSON.stringify(next)).run();
}

async function latestStored(env: Env, hostId: string): Promise<{ version: number; body: StoredPolicyBody } | null> {
  const r = await env.DB.prepare("SELECT version, body_json FROM policies WHERE host_id=? ORDER BY version DESC LIMIT 1").bind(hostId).first<{ version: number; body_json: string }>();
  return r ? { version: r.version, body: safeJson<StoredPolicyBody>(r.body_json, {}) } : null;
}

export function mergeStored(def: StoredPolicyBody, host: StoredPolicyBody): Required<StoredPolicyBody> {
  const now = Date.now();
  const watchKey = (w: { kind: string; target: string }) => `${w.kind}:${w.target}`;
  const watches = new Map<string, { kind: "path" | "process" | "port"; target: string }>();
  for (const w of [...(BUILTIN_DEFAULT.watches), ...(def.watches ?? []), ...(host.watches ?? [])]) watches.set(watchKey(w), w);
  const supp = new Map<string, { fingerprint: string; expires_at: string; reason: string }>();
  for (const s of [...(def.suppressions ?? []), ...(host.suppressions ?? [])]) if (Date.parse(s.expires_at) > now) supp.set(s.fingerprint, s);
  return {
    log_level: host.log_level ?? def.log_level ?? BUILTIN_DEFAULT.log_level,
    thresholds: { ...BUILTIN_DEFAULT.thresholds, ...(def.thresholds ?? {}), ...(host.thresholds ?? {}) },
    watches: [...watches.values()],
    suppressions: [...supp.values()],
  };
}

export async function effectiveThresholds(env: Env, hostId: string): Promise<Record<string, number>> {
  const def = await latestStored(env, "default");
  const host = await latestStored(env, hostId);
  return mergeStored(def?.body ?? {}, host?.body ?? {}).thresholds;
}

/** Full policy body for a host: default + overrides + active/shadow rules + watched IOCs + server endpoints. */
export async function buildPolicyBody(env: Env, hostId: string): Promise<PolicyBody> {
  const def = await latestStored(env, "default");
  const host = await latestStored(env, hostId);
  const merged = mergeStored(def?.body ?? {}, host?.body ?? {});
  const rules = await env.DB.prepare("SELECT id, status, yaml FROM rules WHERE status IN ('active','shadow') ORDER BY id").all<{ id: string; status: "active" | "shadow"; yaml: string }>();
  const iocs = await env.DB.prepare("SELECT type, value FROM iocs WHERE watch=1 ORDER BY first_seen DESC LIMIT 5000").all<{ type: "ip" | "sha256" | "domain"; value: string }>();
  return { ...merged, rules: rules.results, iocs: iocs.results, server_endpoints: await getServerEndpoints(env) };
}

export async function signedPolicy(env: Env, host: Pick<HostRow, "id" | "policy_version">): Promise<SignedEnvelope> {
  const body = await buildPolicyBody(env, host.id);
  return signEnvelope(env.SIGNING_KEY_JWK, { host_id: host.id, version: host.policy_version, issued_at: nowIso(), body });
}

async function notifyHost(env: Env, hostId: string, version: number): Promise<void> {
  try {
    await hostStub(env, hostId).notifyPolicy(version);
  } catch {
    /* host will pick it up on heartbeat */
  }
}

/** Create a new stored policy version for a host and notify it. `mutate` receives the current stored override body. */
export async function updateHostPolicy(
  env: Env,
  hostId: string,
  actor: string,
  reason: string,
  mutate: (cur: StoredPolicyBody) => StoredPolicyBody,
): Promise<number> {
  const cur = await latestStored(env, hostId);
  const next = mutate(cur?.body ?? {});
  const version = (cur?.version ?? 0) + 1;
  const now = nowIso();
  const writes = [
    env.DB.prepare("INSERT INTO policies(host_id, version, body_json, created_by, reason, created_at) VALUES (?,?,?,?,?,?)").bind(hostId, version, JSON.stringify(next), actor, reason, now),
  ];
  if (hostId !== "default") writes.push(env.DB.prepare("UPDATE hosts SET policy_version=? WHERE id=?").bind(version, hostId));
  await env.DB.batch(writes);
  if (hostId === "default") {
    await bumpAllHosts(env, actor, reason);
  } else {
    await notifyHost(env, hostId, version);
  }
  await audit(env, { actor, event: "policy.updated", host_id: hostId, detail: { version, reason } });
  await publish(env, "policy", { host_id: hostId, version, created_by: actor, reason, created_at: now });
  return version;
}

/** Fleet-wide change (rules/IOCs/default policy): new policy version for every host, then notify. */
export async function bumpAllHosts(env: Env, actor: string, reason: string): Promise<number> {
  const hosts = await env.DB.prepare("SELECT id, policy_version FROM hosts").all<{ id: string; policy_version: number }>();
  const now = nowIso();
  const stmts: D1PreparedStatement[] = [];
  const bumped: { id: string; v: number }[] = [];
  for (const h of hosts.results) {
    const cur = await env.DB.prepare("SELECT body_json FROM policies WHERE host_id=? ORDER BY version DESC LIMIT 1").bind(h.id).first<{ body_json: string }>();
    const v = h.policy_version + 1;
    stmts.push(env.DB.prepare("INSERT OR IGNORE INTO policies(host_id, version, body_json, created_by, reason, created_at) VALUES (?,?,?,?,?,?)").bind(h.id, v, cur?.body_json ?? "{}", actor, reason, now));
    stmts.push(env.DB.prepare("UPDATE hosts SET policy_version=? WHERE id=?").bind(v, h.id));
    bumped.push({ id: h.id, v });
  }
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
  await Promise.all(bumped.map((b) => notifyHost(env, b.id, b.v)));
  if (bumped.length) await audit(env, { actor, event: "policy.fleet_bump", detail: { reason, hosts: bumped.length } });
  return bumped.length;
}

/** Tier-0/1 policy actions applied server-side. Returns a result object for actions.result_json. */
export async function applyPolicyAction(
  env: Env,
  hostId: string,
  action: string,
  params: Record<string, unknown>,
  actor: string,
  reason: string,
): Promise<Record<string, unknown>> {
  const now = nowIso();
  switch (action) {
    case "adjust_threshold": {
      const key = String(params.key);
      const value = Number(params.value);
      const version = await updateHostPolicy(env, hostId, actor, reason, (b) => ({ ...b, thresholds: { ...(b.thresholds ?? {}), [key]: value } }));
      return { policy_version: version };
    }
    case "add_watch": {
      const w = { kind: params.kind as "path" | "process" | "port", target: String(params.target) };
      const version = await updateHostPolicy(env, hostId, actor, reason, (b) => ({
        ...b,
        watches: [...(b.watches ?? []).filter((x) => !(x.kind === w.kind && x.target === w.target)), w],
      }));
      return { policy_version: version };
    }
    case "suppress": {
      const expires = new Date(Date.now() + Number(params.ttl_seconds) * 1000).toISOString();
      const s = { fingerprint: String(params.fingerprint), expires_at: expires, reason: String(params.reason ?? reason).slice(0, 300) };
      const version = await updateHostPolicy(env, hostId, actor, reason, (b) => ({
        ...b,
        suppressions: [...(b.suppressions ?? []).filter((x) => x.fingerprint !== s.fingerprint && Date.parse(x.expires_at) > Date.now()), s],
      }));
      return { policy_version: version, expires_at: expires };
    }
    case "propose_rule": {
      const { lintSigma } = await import("../sigma/lint");
      const lint = lintSigma(String(params.yaml));
      if (!lint.ok || !lint.rule) throw new Error("rule lint failed: " + lint.errors.join("; "));
      const r = lint.rule;
      let id = r.id;
      const exists = await env.DB.prepare("SELECT id FROM rules WHERE id=?").bind(id).first();
      if (exists) id = `${id}-ai-${crypto.randomUUID().slice(0, 8)}`;
      const yamlText = exists ? String(params.yaml).replace(/^id:.*$/m, `id: ${id}`) : String(params.yaml);
      await env.DB.prepare(
        "INSERT INTO rules(id, pack_id, title, level, logsource, attack_tags_json, yaml, status, created_by, shadow_since, created_at, updated_at) VALUES (?,?,?,?,?,?,?,'shadow',?,?,?,?)",
      ).bind(id, "ai", r.title, r.level, r.logsource, JSON.stringify(r.tags), yamlText, actor, now, now, now).run();
      await bumpAllHosts(env, actor, `rule ${id} proposed (shadow)`);
      return { rule_id: id, status: "shadow" };
    }
    case "promote_rule":
    case "disable_rule": {
      const status = action === "promote_rule" ? "active" : "disabled";
      const id = String(params.rule_id);
      const res = await env.DB.prepare("UPDATE rules SET status=?, updated_at=?, shadow_since=CASE WHEN ?='active' THEN NULL ELSE shadow_since END WHERE id=?").bind(status, now, status, id).run();
      if (!res.meta.changes) throw new Error("rule not found");
      await bumpAllHosts(env, actor, `rule ${id} -> ${status}`);
      return { rule_id: id, status };
    }
    default:
      throw new Error(`not a policy action: ${action}`);
  }
}
