import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useHost, usePolicies, useSetHostAutonomy, useSetPolicy } from "../api/hooks";
import type { AutonomyMode, PolicyBody } from "../api/types";
import { ActionTable } from "../components/ActionTable";
import { SeverityBadge, StateBadge } from "../components/badges";
import { CodeEditor } from "../components/CodeEditor";
import { Card, Empty, ErrorBox, Field, KV, Loading, PageHeader, Tabs } from "../components/ui";
import { diffLines } from "../lib/diff";
import { ago, fmtTime, isOffline, stringify } from "../lib/format";

function PolicyPanel({ hostId }: { hostId: string }) {
  const hist = usePolicies(hostId);
  const set = useSetPolicy();
  const rows = useMemo(() => [...(hist.data ?? [])].sort((a, b) => b.version - a.version), [hist.data]);
  const [from, setFrom] = useState<number | null>(null);
  const [to, setTo] = useState<number | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);
  if (hist.isLoading) return <Loading what="policies" />;
  if (!rows.length) return <Empty>No policy versions.</Empty>;
  const latest = rows[0];
  const a = rows.find((r) => r.version === (from ?? rows[1]?.version ?? latest.version));
  const b = rows.find((r) => r.version === (to ?? latest.version));
  const diff = a && b ? diffLines(stringify(a.body), stringify(b.body)) : [];
  const save = () => {
    setErr(null);
    let body: PolicyBody;
    try { body = JSON.parse(draft ?? "") as PolicyBody; } catch { setErr("Policy is not valid JSON."); return; }
    if (!reason.trim()) { setErr("A reason is required."); return; }
    set.mutate({ hostId, body, reason: reason.trim() }, { onSuccess: () => { setDraft(null); setReason(""); } });
  };
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto"><table className="tbl">
        <thead><tr><th>Version</th><th>Created</th><th>By</th><th>Reason</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.version}><td className="mono">v{r.version}</td><td className="mono whitespace-nowrap">{fmtTime(r.created_at)}</td><td className="mono">{r.created_by}</td><td>{r.reason ?? "-"}</td></tr>)}</tbody>
      </table></div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted">Diff</span>
        <select aria-label="From version" className="input" value={a?.version} onChange={(e) => setFrom(Number(e.target.value))}>{rows.map((r) => <option key={r.version} value={r.version}>v{r.version}</option>)}</select>
        <span>to</span>
        <select aria-label="To version" className="input" value={b?.version} onChange={(e) => setTo(Number(e.target.value))}>{rows.map((r) => <option key={r.version} value={r.version}>v{r.version}</option>)}</select>
      </div>
      <pre className="mono max-h-96 overflow-auto rounded border border-line bg-bg p-2" aria-label="Policy diff">
        {diff.map((l, i) => <div key={i} style={{ background: l.kind === "add" ? "color-mix(in srgb, #2fa66a 22%, transparent)" : l.kind === "del" ? "color-mix(in srgb, var(--sev-critical) 22%, transparent)" : undefined }}>{l.kind === "add" ? "+ " : l.kind === "del" ? "- " : "  "}{l.text}</div>)}
      </pre>
      {draft === null ? (
        <button type="button" className="btn" onClick={() => setDraft(stringify(latest.body))}>Edit policy (from v{latest.version})</button>
      ) : (
        <div className="space-y-2">
          <CodeEditor lang="json" label="Policy JSON" height="360px" value={draft} onChange={setDraft} />
          <Field label="Reason (required)"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          {(err || set.error) && <ErrorBox error={err ? new Error(err) : set.error} />}
          <div className="flex gap-2"><button type="button" className="btn btn-primary" disabled={set.isPending} onClick={save}>Sign and push new version</button><button type="button" className="btn" onClick={() => setDraft(null)}>Cancel</button></div>
        </div>
      )}
    </div>
  );
}

export function HostDetail() {
  const { id = "" } = useParams();
  const q = useHost(id);
  const auto = useSetHostAutonomy();
  const [tab, setTab] = useState<"overview" | "actions" | "policy">("overview");
  if (q.isLoading) return <Loading what="host" />;
  if (q.error || !q.data) return <ErrorBox error={q.error} />;
  const { host: h, anomalies, incidents, actions } = q.data;
  const off = isOffline(h.last_seen);
  return (
    <>
      <PageHeader title={<span className="mono">{h.hostname}</span>}>
        {off ? <StateBadge state="offline" /> : <StateBadge state={h.status} />}
        <label className="flex items-center gap-2 text-xs text-muted">Autonomy override
          <select className="input" value={h.autonomy ?? ""} disabled={auto.isPending}
            onChange={(e) => auto.mutate({ id: h.id, mode: (e.target.value || null) as AutonomyMode | null })}>
            <option value="">Inherit global</option><option value="autonomous">autonomous</option><option value="propose_only">propose_only</option><option value="paused">paused</option>
          </select>
        </label>
      </PageHeader>
      {auto.error && <ErrorBox error={auto.error} />}
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "actions", label: `Actions (${actions.length})` }, { id: "policy", label: "Policy" }]} />
      {tab === "overview" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Stats">
            <KV data={{ os: h.os, arch: h.arch, kernel: h.kernel, agent_version: h.agent_version, policy_version: h.policy_version, last_seen: `${fmtTime(h.last_seen)} (${ago(h.last_seen)})`, enrolled_at: fmtTime(h.enrolled_at), ...(h.stats ?? {}) }} />
          </Card>
          <Card title={`Rule load errors (${h.rule_errors?.length ?? 0})`}>
            {h.rule_errors?.length ? <ul className="mono space-y-1">{h.rule_errors.map((e) => <li key={e.rule_id}><span className="text-sev-high">{e.rule_id}</span>: {e.error}</li>)}</ul> : <Empty>All rules loaded cleanly.</Empty>}
          </Card>
          <Card title="Incidents">
            {incidents.length ? <ul className="space-y-1.5">{incidents.map((i) => <li key={i.id} className="flex items-center gap-2"><SeverityBadge severity={i.severity} /><Link className="text-muted underline-offset-2 hover:text-fg hover:underline" to={`/incidents/${i.id}`}>{i.title}</Link><StateBadge state={i.status} /></li>)}</ul> : <Empty>No incidents.</Empty>}
          </Card>
          <Card title="Recent anomalies">
            {anomalies.length ? <ul className="space-y-1.5">{anomalies.slice(0, 15).map((a) => <li key={a.id} className="flex items-start gap-2"><SeverityBadge severity={a.severity} /><span className="flex-1">{a.summary}</span><span className="text-muted whitespace-nowrap">{ago(a.ts)}</span></li>)}</ul> : <Empty>No anomalies.</Empty>}
          </Card>
        </div>
      )}
      {tab === "actions" && <Card title="Action history"><ActionTable actions={actions} hostname={h.hostname} /></Card>}
      {tab === "policy" && <Card title="Policy history"><PolicyPanel hostId={h.id} /></Card>}
    </>
  );
}
