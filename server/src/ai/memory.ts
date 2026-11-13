import { logError, truncate } from "../lib/util";
import { aiRunRaw } from "./runner";

export const EMBED_MODEL = "@cf/baai/bge-base-en-v1.5";

export interface MemoryMeta extends Record<string, VectorizeVectorMetadataValue> {
  incident_id: string;
  host_id: string;
  title: string;
  verdict: string;
  label: string; // analyst label or ""
  severity: string;
  summary: string;
  rule_ids: string;
}

export async function embed(env: Env, text: string): Promise<number[] | null> {
  try {
    const out = (await aiRunRaw(env, EMBED_MODEL, { text: [truncate(text, 6000)] })) as { data?: number[][] };
    const v = out?.data?.[0];
    return Array.isArray(v) && v.length === 768 ? v : null;
  } catch (e) {
    logError("embed failed", e);
    return null;
  }
}

export async function rememberIncident(env: Env, meta: MemoryMeta, text: string): Promise<boolean> {
  try {
    const vec = await embed(env, text);
    if (!vec) return false;
    await env.MEMORY.upsert([{ id: meta.incident_id, values: vec, metadata: meta }]);
    return true;
  } catch (e) {
    logError("memory upsert failed", e, { incident_id: meta.incident_id });
    return false;
  }
}

export interface SimilarIncident {
  incident_id: string;
  score: number;
  title: string;
  verdict: string;
  label: string;
  severity: string;
  summary: string;
}

export async function findSimilar(env: Env, text: string, excludeId: string, topK = 4): Promise<SimilarIncident[]> {
  try {
    const vec = await embed(env, text);
    if (!vec) return [];
    const res = await env.MEMORY.query(vec, { topK: topK + 1, returnMetadata: "all" });
    return res.matches
      .filter((m) => m.id !== excludeId && m.score >= 0.6)
      .slice(0, topK)
      .map((m) => {
        const md = (m.metadata ?? {}) as Record<string, string>;
        return { incident_id: m.id, score: Number(m.score.toFixed(3)), title: md.title ?? "", verdict: md.verdict ?? "", label: md.label ?? "", severity: md.severity ?? "", summary: md.summary ?? "" };
      });
  } catch (e) {
    logError("memory query failed", e);
    return [];
  }
}
