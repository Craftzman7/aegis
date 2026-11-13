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
  const map = { open: ["var(--ok)", "Live"], connecting: ["var(--sev-medium)", "Connecting"], closed: ["var(--sev-high)", "Polling (15s)"] } as const;
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
      <nav aria-label="Main" className="flex shrink-0 flex-row gap-0.5 overflow-x-auto border-b border-line p-3 md:w-52 md:flex-col md:border-b-0 md:border-r">
        <Link to="/" className="mb-0 flex items-center gap-2 px-2.5 py-1 text-[15px] font-semibold tracking-tight md:mb-5">
          <span className="h-2.5 w-2.5 rounded-sm bg-fg" aria-hidden="true" />Aegis
        </Link>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => `flex items-center justify-between gap-2 whitespace-nowrap rounded-md px-2.5 py-1.5 ${isActive ? "bg-panel2 font-medium text-fg" : "text-muted hover:text-fg"}`}>
            {n.label}
            {n.to === "/approvals" && pending > 0 && (
              <span aria-label={`${pending} pending`} className="num min-w-5 rounded-full bg-sev-high/15 px-1.5 text-center text-xs font-medium text-sev-high">{pending}</span>
            )}
          </NavLink>
        ))}
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center justify-end gap-5 border-b border-line px-6">
          {autonomy.data && <Link to="/settings" className="flex items-center gap-2 text-xs text-muted hover:text-fg">AI autonomy <StateBadge state={autonomy.data.mode} /></Link>}
          <ConnectionIndicator />
          <span className="text-xs text-muted">{me.data?.email ?? "..."}</span>
        </header>
        <main id="main" className="min-w-0 flex-1 overflow-auto"><div className="mx-auto max-w-6xl px-6 py-6"><Outlet /></div></main>
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
        <div key={t.id} role="alert" className="card flex items-start gap-3 p-3 shadow-lg">
          <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: t.kind === "crit" ? "var(--sev-critical)" : "var(--sev-high)" }} aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="font-medium">{t.title}</div>
            {t.body && <div className="truncate text-muted">{t.body}</div>}
            {t.href && <Link to={t.href} className="text-xs font-medium hover:underline" onClick={() => dismiss(t.id)}>View</Link>}
          </div>
          <button type="button" aria-label="Dismiss" className="text-muted hover:text-fg" onClick={() => dismiss(t.id)}>×</button>
        </div>
      ))}
    </div>
  );
}
