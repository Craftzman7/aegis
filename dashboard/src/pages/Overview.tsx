import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useOverview } from "../api/hooks";
import { SEVERITIES } from "../api/types";
import { describeLive, useLive } from "../live/LiveProvider";
import { sevColor, SeverityBadge } from "../components/badges";
import { Card, ErrorBox, Loading, PageHeader, Empty } from "../components/ui";
import { fmtClock } from "../lib/format";

function Tile({ label, value, color, to }: { label: string; value: number | string; color?: string; to?: string }) {
  const inner = (
    <div className="px-4 py-3.5">
      <div className="label">{label}</div>
      <div className="num mt-1 text-2xl font-semibold tracking-tight" style={{ color }}>{value}</div>
    </div>
  );
  return to ? <Link to={to} className="block transition-colors hover:bg-panel2">{inner}</Link> : inner;
}

export function Overview() {
  const q = useOverview();
  const { ticker } = useLive();
  if (q.isLoading) return <Loading what="overview" />;
  if (q.error || !q.data) return <ErrorBox error={q.error} />;
  const o = q.data;
  const hourly = o.anomalies_24h_hourly.map((h) => ({ ...h, label: new Date(h.hour).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false }) }));
  const openTotal = SEVERITIES.reduce((n, s) => n + (o.incidents_by_severity[s] ?? 0), 0);
  return (
    <>
      <PageHeader title="Overview" />
      <div className="card mb-4 grid grid-cols-2 divide-line overflow-hidden lg:grid-cols-6 [&>*]:border-line [&>*:not(:last-child)]:border-r">
        <Tile label="Hosts online" value={`${o.hosts.online} / ${o.hosts.total}`} to="/hosts" />
        <Tile label="Offline" value={o.hosts.offline} color={o.hosts.offline ? "var(--sev-high)" : undefined} to="/hosts" />
        <Tile label="Isolated" value={o.hosts.isolated} color={o.hosts.isolated ? "var(--sev-critical)" : undefined} to="/hosts" />
        <Tile label="Open incidents" value={openTotal} to="/incidents" />
        <Tile label="Pending approvals" value={o.pending_approvals} color={o.pending_approvals ? "var(--sev-high)" : undefined} to="/approvals" />
        <Tile label="AI actions, 24h" value={o.ai_actions_24h} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Anomalies" actions={<span className="label">Last 24 hours</span>} className="lg:col-span-2">
          <div style={{ height: 220 }} role="img" aria-label="Hourly anomaly counts for the last 24 hours">
            <ResponsiveContainer>
              <BarChart data={hourly}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" vertical={false} />
                <XAxis dataKey="label" stroke="var(--muted)" fontSize={11} interval={3} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--muted)" fontSize={11} allowDecimals={false} width={28} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} cursor={{ fill: "var(--panel2)" }} />
                <Bar dataKey="count" name="Anomalies" fill="var(--muted)" fillOpacity={0.55} radius={[3, 3, 0, 0]} maxBarSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Open incidents" actions={<span className="label">By severity</span>}>
          <ul className="space-y-3">
            {SEVERITIES.map((s) => (
              <li key={s} className="flex items-center gap-2">
                <Link to={`/incidents?severity=${s}`} className="w-20"><SeverityBadge severity={s} /></Link>
                <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel2"><span className="block h-full" style={{ width: `${openTotal ? ((o.incidents_by_severity[s] ?? 0) / openTotal) * 100 : 0}%`, background: sevColor(s) }} /></span>
                <span className="num w-6 text-right text-muted">{o.incidents_by_severity[s] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Live events" className="lg:col-span-3">
          {ticker.length === 0 ? <Empty>Waiting for events...</Empty> : (
            <ul className="max-h-64 divide-y divide-line overflow-auto" aria-live="off">
              {ticker.map((t) => (
                <li key={t.key} className="flex items-baseline gap-4 py-1.5"><time className="num mono shrink-0 text-muted">{fmtClock(t.msg.ts)}</time><span className="w-20 shrink-0 text-xs text-muted first-letter:uppercase">{t.msg.type.replace(/_/g, " ")}</span><span className="truncate">{describeLive(t.msg)}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
