import { Link } from "react-router-dom";
import { useHosts } from "../api/hooks";
import { StateBadge } from "../components/badges";
import { Empty, ErrorBox, Loading, PageHeader } from "../components/ui";
import { ago, isOffline } from "../lib/format";

export function Hosts() {
  const q = useHosts();
  return (
    <>
      <PageHeader title="Hosts" />
      <div className="card overflow-x-auto">
        {q.isLoading ? <Loading what="hosts" /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.length ? <Empty>No hosts enrolled. Generate a token in Settings.</Empty> : (
          <table className="tbl">
            <thead><tr><th>Host</th><th>Status</th><th>Last seen</th><th>Agent</th><th>Policy</th><th>Autonomy</th><th>Open incidents</th></tr></thead>
            <tbody>
              {q.data.map((h) => {
                const off = isOffline(h.last_seen);
                return (
                  <tr key={h.id}>
                    <td><Link className="mono font-medium text-accent hover:underline" to={`/hosts/${h.id}`}>{h.hostname}</Link><div className="text-muted">{h.os} {h.arch}</div></td>
                    <td className="space-x-1">{off ? <StateBadge state="offline" /> : <StateBadge state={h.status} />}{off && h.status === "isolated" && <StateBadge state="isolated" />}</td>
                    <td className={off ? "text-sev-high" : "text-muted"}>{ago(h.last_seen)}</td>
                    <td className="mono">{h.agent_version ?? "-"}</td>
                    <td className="mono">v{h.policy_version}</td>
                    <td>{h.autonomy ? <StateBadge state={h.autonomy} /> : <span className="text-muted">inherit</span>}</td>
                    <td className="mono">{h.open_incidents ?? "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
