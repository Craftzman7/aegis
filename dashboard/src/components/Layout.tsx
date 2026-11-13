import { NavLink, Outlet, Link } from "react-router-dom";
import { useApprovals, useGlobalAutonomy, useMe } from "../api/hooks";
import { useLive } from "../live/LiveProvider";
import { StateBadge } from "./badges";

const NAV = [
  { to: "/", label: "Overview", end: true }, { to: "/incidents", label: "Incidents" }, { to: "/approvals", label: "Approvals" },
  { to: "/hosts", label: "Hosts" }, { to: "/rules", label: "Rules" }, { to: "/audit", label: "Audit" }, { to: "/settings", label: "Settings" },
];

function ConnectionIndicator() {
  const { status } = useLive();
  const map = { open: ["#2fa66a", "Live"], connecting: ["var(--sev-medium)", "Connecting"], closed: ["var(--sev-high)", "Polling (15s)"] } as const;
  const [color, text] = map[status];
  return (
    <span className="flex items-center gap-1.5 text-xs text-muted" role="status" aria-label={`Live connection: ${text}`} title={status === "closed" ? "WebSocket disconnected; falling back to 15s polling" : undefined}>
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />{text}
    </span>
  );
}

export function Layout() {
  const approvals = useApprovals();
  const me = useMe();
  const autonomy = useGlobalAutonomy();
  const pending = approvals.data?.length ?? 0;
  return (
    <div className="flex h-full flex-col md:flex-row">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-panel focus:p-2">Skip to content</a>
      <nav aria-label="Main" className="flex shrink-0 flex-row gap-1 overflow-x-auto border-b border-line bg-panel p-2 md:w-48 md:flex-col md:border-b-0 md:border-r">
        <Link to="/" className="mb-0 flex items-center gap-2 px-2 py-1 font-bold tracking-wide md:mb-3">
          <svg width="18" height="18" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7 5 13 12 15 7-2 12-8 12-15V7z" fill="var(--accent)" /></svg>AEGIS
        </Link>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => `flex items-center justify-between gap-2 whitespace-nowrap rounded px-2.5 py-1.5 ${isActive ? "bg-panel2 font-semibold text-fg" : "text-muted hover:bg-panel2 hover:text-fg"}`}>
            {n.label}
            {n.to === "/approvals" && pending > 0 && (
              <span aria-label={`${pending} pending`} className="rounded-full bg-sev-high px-1.5 text-[11px] font-bold text-white">{pending}</span>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-4 border-b border-line bg-panel px-4 py-2">
          {autonomy.data && <span className="flex items-center gap-1.5 text-xs text-muted">AI autonomy <StateBadge state={autonomy.data.mode} /></span>}
          <ConnectionIndicator />
          <span className="mono text-xs text-muted">{me.data?.email ?? "..."}</span>
        </header>
        <main id="main" className="min-w-0 flex-1 overflow-auto p-4"><Outlet /></main>
      </div>
      <Toasts />
    </div>
  );
}

function Toasts() {
  const { toasts, dismiss } = useLive();
  return (
    <div className="fixed bottom-4 right-4 z-40 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} role="alert" className="card flex items-start gap-2 p-3 shadow-lg" style={{ borderLeft: `4px solid ${t.kind === "crit" ? "var(--sev-critical)" : "var(--sev-high)"}` }}>
          <div className="min-w-0 flex-1">
            <div className="font-semibold">{t.title}</div>
            {t.body && <div className="truncate text-muted">{t.body}</div>}
            {t.href && <Link to={t.href} className="text-accent hover:underline" onClick={() => dismiss(t.id)}>View</Link>}
          </div>
          <button type="button" aria-label="Dismiss" className="text-muted hover:text-fg" onClick={() => dismiss(t.id)}>x</button>
        </div>
      ))}
    </div>
  );
}
