import { parseIp } from "./policy/gate";
import { safeJson } from "./lib/util";
import type { AnomalyRow, HostRow, IncidentRow, Severity } from "./types";

const SEV_ID: Record<Severity, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

/** OCSF 1.3 Detection Finding (class_uid 2004) for an incident with its anomalies as related events. */
export function incidentToOcsf(inc: IncidentRow, host: HostRow | null, anomalies: AnomalyRow[]) {
  const tags = safeJson<string[]>(inc.attack_tags_json, []);
  const techniques = tags.filter((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t)).map((t) => ({ uid: t.slice(7).toUpperCase(), name: t }));
  const tactics = tags.filter((t) => /^attack\.[a-z_]+$/.test(t) && !/^attack\.t\d/i.test(t)).map((t) => ({ name: t.slice(7) }));
  const created = Date.parse(inc.created_at);
  return {
    class_uid: 2004,
    class_name: "Detection Finding",
    category_uid: 2,
    category_name: "Findings",
    activity_id: 1,
    activity_name: "Create",
    type_uid: 200401,
    time: created,
    severity_id: SEV_ID[inc.severity] ?? 0,
    severity: inc.severity,
    confidence_score: inc.confidence === null ? undefined : Math.round(inc.confidence * 100),
    status: inc.status,
    message: inc.title,
    metadata: { version: "1.3.0", product: { name: "Aegis", vendor_name: "Aegis" }, uid: inc.id },
    finding_info: {
      uid: inc.id,
      title: inc.title,
      desc: inc.ai_summary ?? undefined,
      created_time: created,
      modified_time: Date.parse(inc.updated_at),
      types: [inc.verdict ?? "unknown"],
      attacks: techniques.map((t, i) => ({ technique: t, tactic: tactics[i] ?? tactics[0] })),
      related_events: anomalies.map((a) => ({ uid: a.id, type: a.rule_id, product: { name: a.rule_source } })),
    },
    device: host ? { uid: host.id, hostname: host.hostname, os: { name: host.os ?? "linux" }, type_id: 1 } : undefined,
    evidences: anomalies.map((a) => ({
      process: undefined,
      data: { rule_id: a.rule_id, rule_title: a.rule_title, severity: a.severity, summary: a.summary, ts: a.ts, fingerprint: a.fingerprint, evidence: safeJson(a.evidence_json, null), evidence_r2_key: a.evidence_r2_key },
    })),
    unmapped: { verdict: inc.verdict, analyst_note: inc.analyst_note },
  };
}

export interface IocRow {
  id: string;
  type: string;
  value: string;
  source: string;
  first_seen: string;
}

export function iocsToStix(iocs: IocRow[]) {
  const objects = iocs.map((i) => {
    const v = i.value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    const pattern =
      i.type === "ip" ? `[${i.value.includes(":") ? "ipv6-addr" : "ipv4-addr"}:value = '${v}']` : i.type === "sha256" ? `[file:hashes.'SHA-256' = '${v}']` : `[domain-name:value = '${v}']`;
    return {
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${i.id}`,
      created: i.first_seen,
      modified: i.first_seen,
      name: `${i.type}:${i.value}`,
      description: `Aegis IOC (source: ${i.source})`,
      indicator_types: ["malicious-activity"],
      pattern,
      pattern_type: "stix",
      valid_from: i.first_seen,
    };
  });
  return { type: "bundle", id: `bundle--${crypto.randomUUID()}`, objects };
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$/;

export function normalizeIoc(type: string, value: string): { type: "ip" | "sha256" | "domain"; value: string } | null {
  const t = type.trim().toLowerCase();
  const v = value.trim();
  if (t === "ip" || t === "ipv4" || t === "ipv6" || t === "ipv4-addr" || t === "ipv6-addr") return parseIp(v) ? { type: "ip", value: v.toLowerCase() } : null;
  if (t === "sha256" || t === "sha-256") return /^[0-9a-fA-F]{64}$/.test(v) ? { type: "sha256", value: v.toLowerCase() } : null;
  if (t === "domain" || t === "domain-name" || t === "hostname") return DOMAIN_RE.test(v.toLowerCase()) ? { type: "domain", value: v.toLowerCase() } : null;
  return null;
}

export function parseIocCsv(text: string): { iocs: { type: "ip" | "sha256" | "domain"; value: string }[]; errors: string[] } {
  const iocs: { type: "ip" | "sha256" | "domain"; value: string }[] = [];
  const errors: string[] = [];
  text.split(/\r?\n/).forEach((line, idx) => {
    const l = line.trim();
    if (!l || l.startsWith("#")) return;
    const [t, ...rest] = l.split(",");
    if (idx === 0 && t!.trim().toLowerCase() === "type") return;
    const n = normalizeIoc(t ?? "", rest.join(",").replace(/^"|"$/g, ""));
    if (n) iocs.push(n);
    else errors.push(`line ${idx + 1}: invalid ioc`);
  });
  return { iocs, errors };
}

export function parseStixBundle(bundle: unknown): { iocs: { type: "ip" | "sha256" | "domain"; value: string }[]; errors: string[] } {
  const iocs: { type: "ip" | "sha256" | "domain"; value: string }[] = [];
  const errors: string[] = [];
  const objs = (bundle as { objects?: unknown[] })?.objects;
  if (!Array.isArray(objs)) return { iocs, errors: ["not a STIX bundle (missing objects[])"] };
  for (const o of objs) {
    const ind = o as { type?: string; pattern?: string; id?: string };
    if (ind?.type !== "indicator" || typeof ind.pattern !== "string") continue;
    let found = false;
    const pats: [RegExp, string][] = [
      [/ipv[46]-addr:value\s*=\s*'([^']+)'/g, "ip"],
      [/file:hashes\.(?:'SHA-256'|"SHA-256"|SHA-256)\s*=\s*'([^']+)'/gi, "sha256"],
      [/domain-name:value\s*=\s*'([^']+)'/g, "domain"],
    ];
    for (const [re, type] of pats) {
      for (const m of ind.pattern.matchAll(re)) {
        const n = normalizeIoc(type, m[1]!);
        if (n) {
          iocs.push(n);
          found = true;
        } else errors.push(`${ind.id ?? "indicator"}: invalid ${type}`);
      }
    }
    if (!found && !errors.length) errors.push(`${ind.id ?? "indicator"}: unsupported pattern`);
  }
  return { iocs, errors: errors.slice(0, 50) };
}
