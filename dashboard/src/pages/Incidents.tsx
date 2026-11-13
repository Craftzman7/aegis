import { Link, useSearchParams } from "react-router-dom";
import { useHosts, useIncidents } from "../api/hooks";
import { SEVERITIES } from "../api/types";
import { ConfidenceBar, SeverityBadge, StateBadge, VerdictBadge } from "../components/badges";
import { AttackTags, Empty, ErrorBox, Loading, PageHeader } from "../components/ui";
import { ago } from "../lib/format";

const STATUSES = ["open", "investigating", "awaiting_approval", "contained", "closed_benign", "closed_tp"];

export function Incidents() {
  const [sp, setSp] = useSearchParams();
  const f = { status: sp.get("status") ?? "", severity: sp.get("severity") ?? "", host: sp.get("host") ?? "" };
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n); };
  const q = useIncidents(f);
  const hosts = useHosts();
  const name = (id: string) => hosts.data?.find((h) => h.id === id)?.hostname ?? id.slice(0, 8);
  return (
    <>
      <PageHeader title="Incidents">
        <select aria-label="Filter by status" className="input" value={f.status} onChange={(e) => set("status", e.target.value)}>
          <option value="">All statuses</option>{STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
        </select>
        <select aria-label="Filter by severity" className="input" value={f.severity} onChange={(e) => set("severity", e.target.value)}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Filter by host" className="input" value={f.host} onChange={(e) => set("host", e.target.value)}>
          <option value="">All hosts</option>{hosts.data?.map((h) => <option key={h.id} value={h.id}>{h.hostname}</option>)}
        </select>
      </PageHeader>
      <div className="card overflow-x-auto">
        {q.isLoading ? <Loading what="incidents" /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.length ? <Empty>No incidents match.</Empty> : (
          <table className="tbl">
            <thead><tr><th>Severity</th><th>Title</th><th>Host</th><th>Status</th><th>Verdict</th><th>Confidence</th><th>ATT&amp;CK</th><th>Updated</th></tr></thead>
            <tbody>
              {q.data.map((i) => (
                <tr key={i.id}>
                  <td><SeverityBadge severity={i.severity} /></td>
                  <td><Link className="font-medium text-accent hover:underline" to={`/incidents/${i.id}`}>{i.title}</Link></td>
                  <td className="mono">{i.hostname ?? name(i.host_id)}</td>
                  <td><StateBadge state={i.status} /></td>
                  <td><VerdictBadge verdict={i.verdict} /></td>
                  <td><ConfidenceBar value={i.confidence} /></td>
                  <td><AttackTags tags={i.attack_tags} /></td>
                  <td className="whitespace-nowrap text-muted">{ago(i.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
