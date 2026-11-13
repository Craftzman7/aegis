import type { ReactNode } from "react";
import type { ActionState, IncidentStatus, Severity, Verdict } from "../api/types";

const sevVar: Record<Severity, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)",
};
export const sevColor = (s: Severity) => sevVar[s] ?? sevVar.info;

export function Pill({ color, children, title }: { color: string; children: ReactNode; title?: string }) {
  return (
    <span title={title} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide whitespace-nowrap"
      style={{ color, border: `1px solid ${color}`, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill color={sevColor(severity)}>{severity}</Pill>;
}

const stateColors: Record<string, string> = {
  proposed: "var(--sev-medium)", approved: "var(--sev-low)", dispatched: "var(--sev-low)", succeeded: "#2fa66a",
  failed: "var(--sev-critical)", rejected: "var(--sev-high)", rolled_back: "var(--sev-info)", expired: "var(--sev-info)",
  open: "var(--sev-high)", investigating: "var(--sev-low)", awaiting_approval: "var(--sev-medium)", contained: "#2fa66a",
  closed_benign: "var(--sev-info)", closed_tp: "#2fa66a",
  ok: "#2fa66a", degraded: "var(--sev-medium)", isolated: "var(--sev-critical)", offline: "var(--sev-info)",
  active: "#2fa66a", shadow: "var(--sev-medium)", disabled: "var(--sev-info)",
  autonomous: "#2fa66a", propose_only: "var(--sev-medium)", paused: "var(--sev-critical)",
};
export function StateBadge({ state }: { state: ActionState | IncidentStatus | string }) {
  return <Pill color={stateColors[state] ?? "var(--sev-info)"}>{state.replace(/_/g, " ")}</Pill>;
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
      <span className="h-1.5 w-20 overflow-hidden rounded bg-panel2 border border-line">
        <span className="block h-full bg-accent" style={{ width: `${v * 100}%` }} />
      </span>
      <span className="mono">{value == null ? "-" : `${Math.round(v * 100)}%`}</span>
    </span>
  );
}
