import type {
  ActionName, ActionRow, AutonomyMode, Approval, AuditEntry, Coverage, Host, HostDetail, Incident,
  IncidentDetail, JsonObject, LintResult, Overview, PolicyBody, PolicyRow, Rule, RuleStatus, TestResult,
} from "./types";

const BASE = "/console/api";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown, raw?: BodyInit): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let payload: BodyInit | undefined = raw;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, { method, headers, body: payload, credentials: "same-origin" });
  const text = await res.text();
  if (!res.ok) {
    let msg = text || res.statusText;
    try {
      const j = JSON.parse(text) as { error?: string; message?: string };
      msg = j.error ?? j.message ?? msg;
    } catch { /* not JSON */ }
    throw new ApiError(res.status, msg);
  }
  return (text ? JSON.parse(text) : {}) as T;
}

/** Lists may come back as a bare array or wrapped in `{[key]: [...]}`; accept both. */
function unwrap<T>(v: T[] | Record<string, unknown>, key: string): T[] {
  if (Array.isArray(v)) return v;
  const inner = v[key];
  return Array.isArray(inner) ? (inner as T[]) : [];
}
const qs = (p: Record<string, string | number | undefined>) => {
  const s = Object.entries(p).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join("&");
  return s ? `?${s}` : "";
};

export const api = {
  me: () => request<{ email: string }>("GET", "/me"),
  overview: () => request<Overview>("GET", "/overview"),

  hosts: async () => unwrap<Host>(await request("GET", "/hosts"), "hosts"),
  host: (id: string) => request<HostDetail>("GET", `/hosts/${id}`),
  setHostAutonomy: (id: string, mode: AutonomyMode | null) => request<{ ok?: boolean }>("POST", `/hosts/${id}/autonomy`, { mode }),
  getAutonomy: () => request<{ mode: AutonomyMode }>("GET", "/settings/autonomy"),
  setAutonomy: (mode: AutonomyMode) => request<{ mode: AutonomyMode }>("POST", "/settings/autonomy", { mode }),

  incidents: async (f: { status?: string; severity?: string; host?: string }) =>
    unwrap<Incident>(await request("GET", `/incidents${qs(f)}`), "incidents"),
  incident: (id: string) => request<IncidentDetail>("GET", `/incidents/${id}`),
  verdict: (id: string, verdict: "true_positive" | "false_positive", note: string) =>
    request<{ ok?: boolean }>("POST", `/incidents/${id}/verdict`, { verdict, note }),
  ask: (id: string, question: string) => request<{ answer: string }>("POST", `/incidents/${id}/ask`, { question }),

  approvals: async () => unwrap<Approval>(await request("GET", "/approvals"), "approvals"),
  approve: (id: string, b: { params?: JsonObject; ttl_seconds?: number }) => request<{ ok?: boolean }>("POST", `/actions/${id}/approve`, b),
  reject: (id: string, reason: string) => request<{ ok?: boolean }>("POST", `/actions/${id}/reject`, { reason }),
  rollback: (id: string) => request<{ ok?: boolean }>("POST", `/actions/${id}/rollback`),
  manualAction: (b: { host_id: string; action: ActionName; params: JsonObject; incident_id?: string }) =>
    request<ActionRow>("POST", "/actions", b),

  audit: async (f: { limit?: number; before?: number }) => unwrap<AuditEntry>(await request("GET", `/audit${qs(f)}`), "entries"),

  rules: async () => unwrap<Rule>(await request("GET", "/rules"), "rules"),
  createRule: (yaml: string, status: RuleStatus) => request<Rule>("POST", "/rules", { yaml, status }),
  setRuleStatus: (id: string, status: RuleStatus) => request<{ ok?: boolean }>("POST", `/rules/${id}/status`, { status }),
  lintRule: (yaml: string) => request<LintResult>("POST", "/rules/lint", { yaml }),
  /** Tests a rule on a host. `yaml` is sent too so unsaved drafts can be tested; id "draft" is used for unsaved rules. */
  testRule: (id: string, host_id: string, yaml?: string) => request<TestResult>("POST", `/rules/${id}/test`, { host_id, yaml }),
  coverage: () => request<Coverage>("GET", "/coverage"),

  policies: async (hostId: string) => unwrap<PolicyRow>(await request("GET", `/policies/${hostId}`), "policies"),
  setPolicy: (hostId: string, body: PolicyBody, reason: string) => request<{ ok?: boolean; version?: number }>("POST", `/policies/${hostId}`, { body, reason }),

  createEnrollToken: (ttl_hours: number) => request<{ token: string; expires_at: string }>("POST", "/enroll-tokens", { ttl_hours }),
  importIocs: (content: string, contentType: "application/json" | "text/csv") =>
    request<{ imported?: number }>("POST", "/iocs/import", undefined, new Blob([content], { type: contentType })),
  evidence: (key: string) => request<unknown>("GET", `/evidence${qs({ key })}`),

  ocsfUrl: (incidentId: string) => `${BASE}/export/incidents/${incidentId}.ocsf.json`,
  stixUrl: () => `${BASE}/export/iocs.stix.json`,
};
