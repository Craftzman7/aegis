import { unzipSync } from "fflate";
import { audit } from "../lib/audit";
import { logError, nowIso } from "../lib/util";
import { bumpAllHosts } from "../policy/service";
import { lintSigma } from "./lint";

const UA = { "User-Agent": "aegis-sigma-sync", Accept: "application/vnd.github+json" };

export interface SyncResult {
  tag: string;
  added: number;
  updated: number;
  skipped: number;
  unchanged?: boolean;
}

/** Extract rules/linux/**.yml from a SigmaHQ release zip. */
export function extractLinuxRules(zip: Uint8Array): { path: string; yaml: string }[] {
  const files = unzipSync(zip, { filter: (f) => /(^|\/)rules\/linux\/.+\.ya?ml$/.test(f.name) });
  const dec = new TextDecoder();
  return Object.entries(files).map(([path, data]) => ({ path, yaml: dec.decode(data) }));
}

export async function upsertSigmaRules(env: Env, rules: { path: string; yaml: string }[], packId = "sigmahq"): Promise<Omit<SyncResult, "tag">> {
  const now = nowIso();
  const existing = new Set((await env.DB.prepare("SELECT id FROM rules WHERE pack_id=?").bind(packId).all<{ id: string }>()).results.map((r) => r.id));
  let added = 0, updated = 0, skipped = 0;
  const stmts: D1PreparedStatement[] = [];
  const seen = new Set<string>();
  for (const r of rules) {
    const lint = lintSigma(r.yaml);
    if (!lint.ok || !lint.rule || seen.has(lint.rule.id) || lint.rule.status === "deprecated" || lint.rule.status === "unsupported") {
      skipped++;
      continue;
    }
    seen.add(lint.rule.id);
    const x = lint.rule;
    if (existing.has(x.id)) updated++;
    else added++;
    // New rules land in shadow so they cannot flood; existing rules keep their status.
    stmts.push(
      env.DB.prepare(
        `INSERT INTO rules(id, pack_id, title, level, logsource, attack_tags_json, yaml, status, created_by, shadow_since, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,'shadow','system',?,?,?)
         ON CONFLICT(id) DO UPDATE SET title=excluded.title, level=excluded.level, logsource=excluded.logsource, attack_tags_json=excluded.attack_tags_json, yaml=excluded.yaml, updated_at=excluded.updated_at
         WHERE rules.pack_id=excluded.pack_id`,
      ).bind(x.id, packId, x.title, x.level, x.logsource, JSON.stringify(x.tags), r.yaml, now, now, now),
    );
  }
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
  return { added, updated, skipped };
}

export async function syncSigmaHQ(env: Env, fetcher: typeof fetch = fetch): Promise<SyncResult | null> {
  try {
    const rel = await fetcher("https://api.github.com/repos/SigmaHQ/sigma/releases/latest", { headers: UA });
    if (!rel.ok) throw new Error(`github releases: ${rel.status}`);
    const j = (await rel.json()) as { tag_name: string; assets: { name: string; browser_download_url: string }[] };
    const cur = await env.DB.prepare("SELECT version FROM rule_packs WHERE id='sigmahq'").first<{ version: string }>();
    if (cur?.version === j.tag_name) return { tag: j.tag_name, added: 0, updated: 0, skipped: 0, unchanged: true };
    const asset = j.assets.find((a) => a.name === "sigma_all_rules.zip") ?? j.assets.find((a) => /rules.*\.zip$/.test(a.name));
    if (!asset) throw new Error("no rules zip asset in release");
    const z = await fetcher(asset.browser_download_url, { headers: { "User-Agent": UA["User-Agent"] } });
    if (!z.ok) throw new Error(`download: ${z.status}`);
    const buf = new Uint8Array(await z.arrayBuffer());
    const r2Key = `rules/sigmahq/${j.tag_name}.zip`;
    await env.EVIDENCE.put(r2Key, buf, { httpMetadata: { contentType: "application/zip" } });
    const res = await upsertSigmaRules(env, extractLinuxRules(buf));
    await env.DB.prepare("UPDATE rule_packs SET version=?, r2_key=?, updated_at=? WHERE id='sigmahq'").bind(j.tag_name, r2Key, nowIso()).run();
    if (res.added + res.updated > 0) await bumpAllHosts(env, "system", `SigmaHQ ${j.tag_name} sync`);
    await audit(env, { actor: "system", event: "sigma.synced", detail: { tag: j.tag_name, ...res } });
    return { tag: j.tag_name, ...res };
  } catch (e) {
    logError("sigma sync failed", e);
    await audit(env, { actor: "system", event: "sigma.sync_failed", detail: { error: e instanceof Error ? e.message : String(e) } });
    return null;
  }
}
