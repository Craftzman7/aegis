import type { ReactNode } from "react";
import type { ActionState, IncidentStatus, Severity, Verdict } from "../api/types";

const sevVar: Record<Severity, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)",
};
export const sevColor = (s: Severity) => sevVar[s] ?? sevVar.info;

export function Pill({ color, children, title, dot }: { color: string; children: ReactNode; title?: string; dot?: boolean }) {
  return (
    <span title={title} className="inline-flex h-5 items-center gap-1.5 rounded-md px-1.5 text-xs font-medium whitespace-nowrap first-letter:uppercase"
      style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)` }}>
      {dot && <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} aria-hidden="true" />}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill dot color={sevColor(severity)}>{severity}</Pill>;
}

const stateColors: Record<string, string> = {
  proposed: "var(--sev-medium)", approved: "var(--sev-low)", dispatched: "var(--sev-low)", succeeded: "var(--ok)",
  failed: "var(--sev-critical)", rejected: "var(--sev-high)", rolled_back: "var(--sev-info)", expired: "var(--sev-info)",
  open: "var(--sev-high)", investigating: "var(--sev-low)", awaiting_approval: "var(--sev-medium)", contained: "var(--ok)", resolved: "var(--ok)",
  closed_benign: "var(--sev-info)", closed_tp: "var(--ok)",
  ok: "var(--ok)", degraded: "var(--sev-medium)", isolated: "var(--sev-critical)", offline: "var(--sev-info)",
  active: "var(--ok)", shadow: "var(--sev-medium)", disabled: "var(--sev-info)",
  autonomous: "var(--ok)", propose_only: "var(--sev-medium)", paused: "var(--sev-critical)",
};
export function StateBadge({ state }: { state: ActionState | IncidentStatus | string }) {
  // resolved shares the ok colour with contained; the dot tells them apart
  return <Pill dot={state === "resolved"} color={stateColors[state] ?? "var(--sev-info)"}>{state.replace(/_/g, " ")}</Pill>;
}

const verdictColors: Record<Verdict, string> = {
  malicious: "var(--sev-critical)", true_positive: "var(--sev-critical)", suspicious: "var(--sev-medium)",
  benign: "var(--sev-info)", false_positive: "var(--sev-info)",
};
export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <span className="text-muted">no verdict</span>;
  return <Pill color={verdictColors[verdict]}>{verdict.replace(/_/g, " ")}</Pill>;
}

export function ConfidenceBar({ value }: { value: number | null }) {
  const v = Math.max(0, Math.min(1, value ?? 0));
  return (
    <span className="inline-flex items-center gap-2" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v * 100)} aria-label="confidence">
      <span className="h-1 w-16 overflow-hidden rounded-full bg-panel2">
        <span className="block h-full bg-accent" style={{ width: `${v * 100}%` }} />
      </span>
      <span className="num text-muted">{value == null ? "-" : `${Math.round(v * 100)}%`}</span>
    </span>
  );
}
