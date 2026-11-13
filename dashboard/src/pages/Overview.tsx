import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useOverview } from "../api/hooks";
import { SEVERITIES } from "../api/types";
import { describeLive, useLive } from "../live/LiveProvider";
import { sevColor, SeverityBadge, StateBadge } from "../components/badges";
import { Card, ErrorBox, Loading, PageHeader, Empty } from "../components/ui";
import { fmtClock } from "../lib/format";

function Tile({ label, value, color, to }: { label: string; value: number | string; color?: string; to?: string }) {
  const inner = (
    <div className="card p-3">
      <div className="text-[11px] uppercase tracking-wider text-muted">{label}</div>
      <div className="mono text-2xl font-bold" style={{ color }}>{value}</div>
    </div>
  );
  return to ? <Link to={to} className="block hover:opacity-90">{inner}</Link> : inner;
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
      <PageHeader title="Overview"><span className="flex items-center gap-2 text-xs text-muted">Global autonomy <StateBadge state={o.autonomy} /> <Link to="/settings" className="text-accent hover:underline">change</Link></span></PageHeader>
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-6">
        <Tile label="Hosts online" value={`${o.hosts.online}/${o.hosts.total}`} color="#2fa66a" to="/hosts" />
        <Tile label="Offline" value={o.hosts.offline} color={o.hosts.offline ? "var(--sev-high)" : undefined} to="/hosts" />
        <Tile label="Isolated" value={o.hosts.isolated} color={o.hosts.isolated ? "var(--sev-critical)" : undefined} to="/hosts" />
        <Tile label="Open incidents" value={openTotal} to="/incidents" />
        <Tile label="Pending approvals" value={o.pending_approvals} color={o.pending_approvals ? "var(--sev-high)" : undefined} to="/approvals" />
        <Tile label="AI auto-actions 24h" value={o.ai_actions_24h} color="var(--accent)" />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Anomalies, last 24h (hourly)" className="lg:col-span-2">
          <div style={{ height: 220 }} role="img" aria-label="Hourly anomaly counts for the last 24 hours">
            <ResponsiveContainer>
              <BarChart data={hourly}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" stroke="var(--muted)" fontSize={11} interval={2} />
                <YAxis stroke="var(--muted)" fontSize={11} allowDecimals={false} width={30} />
                <Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)" }} cursor={{ fill: "var(--panel2)" }} />
                <Bar dataKey="count" fill="var(--accent)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Open incidents by severity">
          <ul className="space-y-2">
            {SEVERITIES.map((s) => (
              <li key={s} className="flex items-center gap-2">
                <Link to={`/incidents?severity=${s}`} className="w-20"><SeverityBadge severity={s} /></Link>
                <span className="h-2 flex-1 overflow-hidden rounded bg-panel2"><span className="block h-full" style={{ width: `${openTotal ? ((o.incidents_by_severity[s] ?? 0) / openTotal) * 100 : 0}%`, background: sevColor(s) }} /></span>
                <span className="mono w-6 text-right">{o.incidents_by_severity[s] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Live event ticker" className="lg:col-span-3">
          {ticker.length === 0 ? <Empty>Waiting for events...</Empty> : (
            <ul className="mono max-h-64 space-y-0.5 overflow-auto" aria-live="off">
              {ticker.map((t) => (
                <li key={t.key} className="flex gap-3"><time className="shrink-0 text-muted">{fmtClock(t.msg.ts)}</time><span className="w-16 shrink-0 uppercase text-accent">{t.msg.type}</span><span className="truncate">{describeLive(t.msg)}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
