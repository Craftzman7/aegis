import { parse } from "yaml";

export interface LintResult {
  ok: boolean;
  errors: string[];
  rule?: ParsedRule;
}

export interface ParsedRule {
  id: string;
  title: string;
  level: string;
  status?: string;
  logsource: string;
  tags: string[];
  falsepositives: string[];
}

const LEVELS = ["informational", "low", "medium", "high", "critical"];
const MAX_YAML_BYTES = 64 * 1024;

/** Light structural lint of a single Sigma rule (not a full spec validator). */
export function lintSigma(yamlText: string): LintResult {
  const errors: string[] = [];
  if (typeof yamlText !== "string" || yamlText.trim() === "") return { ok: false, errors: ["empty rule"] };
  if (new TextEncoder().encode(yamlText).length > MAX_YAML_BYTES) return { ok: false, errors: ["rule exceeds 64KB"] };
  let doc: unknown;
  try {
    doc = parse(yamlText, { maxAliasCount: 20 });
  } catch (e) {
    return { ok: false, errors: [`YAML parse error: ${e instanceof Error ? e.message : String(e)}`] };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, errors: ["rule must be a YAML mapping"] };
  const r = doc as Record<string, unknown>;
  if (typeof r.title !== "string" || !r.title.trim()) errors.push("missing required field: title");
  else if (r.title.length > 256) errors.push("title too long (>256)");
  if (typeof r.id !== "string" || !r.id.trim()) errors.push("missing required field: id");
  else if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(r.id)) errors.push("id contains invalid characters");
  const ls = r.logsource;
  if (!ls || typeof ls !== "object" || Array.isArray(ls)) errors.push("missing required field: logsource (mapping)");
  else if (Object.keys(ls).length === 0) errors.push("logsource must not be empty");
  const det = r.detection;
  if (!det || typeof det !== "object" || Array.isArray(det)) errors.push("missing required field: detection (mapping)");
  else {
    const d = det as Record<string, unknown>;
    const cond = d.condition;
    if (cond === undefined) errors.push("detection.condition is required");
    else if (!(typeof cond === "string" && cond.trim()) && !(Array.isArray(cond) && cond.length > 0 && cond.every((c) => typeof c === "string")))
      errors.push("detection.condition must be a non-empty string or list of strings");
    const selections = Object.keys(d).filter((k) => k !== "condition" && k !== "timeframe");
    if (selections.length === 0) errors.push("detection needs at least one selection");
    if (typeof cond === "string") {
      const idents = cond.match(/[A-Za-z_][A-Za-z0-9_*]*/g) ?? [];
      const kw = new Set(["and", "or", "not", "of", "all", "them", "1", "count", "by"]);
      for (const id of idents) {
        if (kw.has(id.toLowerCase())) continue;
        if (id.includes("*")) {
          const re = new RegExp("^" + id.replace(/\*/g, ".*") + "$");
          if (!selections.some((s) => re.test(s))) errors.push(`condition references no selection matching '${id}'`);
        } else if (!selections.includes(id)) errors.push(`condition references undefined selection '${id}'`);
      }
    }
  }
  if (typeof r.level !== "string" || !LEVELS.includes(r.level)) errors.push(`level is required and must be one of ${LEVELS.join("|")}`);
  if (r.tags !== undefined && !(Array.isArray(r.tags) && r.tags.every((t) => typeof t === "string"))) errors.push("tags must be a list of strings");
  if (r.falsepositives !== undefined && !Array.isArray(r.falsepositives)) errors.push("falsepositives must be a list");
  if (errors.length) return { ok: false, errors };
  const lsr = ls as Record<string, unknown>;
  return {
    ok: true,
    errors: [],
    rule: {
      id: r.id as string,
      title: (r.title as string).trim(),
      level: r.level as string,
      status: typeof r.status === "string" ? r.status : undefined,
      logsource: ["product", "category", "service"].map((k) => lsr[k]).filter((v) => typeof v === "string").join("/"),
      tags: ((r.tags as string[] | undefined) ?? []).map(String),
      falsepositives: Array.isArray(r.falsepositives) ? (r.falsepositives as unknown[]).map(String) : [],
    },
  };
}

/** Map Sigma level to Aegis severity. */
export function levelToSeverity(level: string): "info" | "low" | "medium" | "high" | "critical" {
  return level === "informational" ? "info" : (LEVELS.includes(level) ? level : "low") as "low";
}
