import { useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { ActionRow, AiReview, Anomaly, AuditEntry } from "../api/types";
import { fmtTime, short } from "../lib/format";
import { ConfidenceBar, Pill, SeverityBadge, StateBadge, VerdictBadge } from "./badges";
import { AttackTags, JsonView, KV } from "./ui";
import { ErrorBox } from "./ui";

export type TimelineItem =
  | { kind: "anomaly"; ts: string; id: string; data: Anomaly }
  | { kind: "review"; ts: string; id: string; data: AiReview }
  | { kind: "action"; ts: string; id: string; data: ActionRow }
  | { kind: "audit"; ts: string; id: string; data: AuditEntry };

export function buildTimeline(a: Anomaly[], r: AiReview[], x: ActionRow[], u: AuditEntry[]): TimelineItem[] {
  const items: TimelineItem[] = [
    ...a.map((d): TimelineItem => ({ kind: "anomaly", ts: d.ts, id: `a${d.id}`, data: d })),
    ...r.map((d): TimelineItem => ({ kind: "review", ts: d.ts, id: `r${d.id}`, data: d })),
    ...x.map((d): TimelineItem => ({ kind: "action", ts: d.created_at, id: `x${d.id}`, data: d })),
    ...u.map((d): TimelineItem => ({ kind: "audit", ts: d.ts, id: `u${d.id}`, data: d })),
  ];
  return items.sort((p, q) => new Date(p.ts).getTime() - new Date(q.ts).getTime());
}

const KIND_LABEL = { anomaly: "Anomaly", review: "AI review", action: "Action", audit: "Audit" } as const;
const KIND_COLOR = { anomaly: "var(--sev-high)", review: "var(--accent)", action: "#2fa66a", audit: "var(--sev-info)" } as const;

function LazyEvidence({ r2Key }: { r2Key: string }) {
  const [want, setWant] = useState(false);
  const q = useQuery({ queryKey: ["evidence", r2Key], queryFn: () => api.evidence(r2Key), enabled: want, staleTime: Infinity });
  if (!want) return <button type="button" className="btn" onClick={() => setWant(true)}>Load full evidence from R2</button>;
  if (q.isLoading) return <span className="text-muted">Fetching evidence...</span>;
  if (q.error) return <ErrorBox error={q.error} />;
  return <JsonView value={q.data} />;
}

function AnomalyBody({ a }: { a: Anomaly }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={a.severity} /><span className="font-medium">{a.rule_title ?? a.rule_id}</span>
        {a.shadow ? <Pill color="var(--sev-medium)">shadow</Pill> : null}
        <span className="mono text-muted">{a.rule_source}</span>
      </div>
      <div>{a.summary}</div>
      <AttackTags tags={a.attack_tags} />
      <div>
        <button type="button" className="text-xs text-accent hover:underline" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide evidence" : "Show evidence"}</button>
      </div>
      {open && (
        <div className="space-y-2">
          {a.evidence && <JsonView value={a.evidence} />}
          {a.evidence_r2_key && <LazyEvidence r2Key={a.evidence_r2_key} />}
          {!a.evidence && !a.evidence_r2_key && <span className="text-muted">No evidence stored.</span>}
          {a.falsepositives.length > 0 && <div className="text-muted">Known false positives: {a.falsepositives.join("; ")}</div>}
          <div className="mono text-muted">fingerprint {short(a.fingerprint)}</div>
        </div>
      )}
    </div>
  );
}

function ReviewBody({ r }: { r: AiReview }) {
  const o = r.output;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{r.step}{r.round ? ` (round ${r.round})` : ""}</span>
        <VerdictBadge verdict={o.verdict} /><SeverityBadge severity={o.severity} /><ConfidenceBar value={o.confidence} />
        <span className="mono text-muted">{r.model}</span>
      </div>
      <p className="whitespace-pre-wrap">{o.rationale}</p>
      {o.requests.length > 0 && (
        <ul className="space-y-1.5">
          {o.requests.map((rq, i) => {
            const g = r.gate?.[i] ?? r.gate?.find((x) => x.action === rq.action);
            return (
              <li key={i} className="rounded border border-line bg-bg p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono font-semibold">{rq.action}</span>
                  {g ? (<>
                    <Pill color={g.accepted ? "#2fa66a" : "var(--sev-critical)"}>{g.accepted ? "accepted" : "rejected"}</Pill>
                    <Pill color="var(--sev-info)">tier {g.tier}</Pill>
                  </>) : <Pill color="var(--sev-info)">no gate decision</Pill>}
                </div>
                <KV data={rq.params} />
                {g && <div className="mt-1 text-muted">Gate: {g.reason}</div>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function ActionBody({ x }: { x: ActionRow }) {
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="mono font-semibold">{x.action}</span><StateBadge state={x.state} /><Pill color="var(--sev-info)">tier {x.tier}</Pill>
        <span className="text-muted">by {x.proposed_by}</span>
      </div>
      <KV data={x.params} />
      {x.rationale && <div className="text-muted">{x.rationale}</div>}
      {x.reject_reason && <div className="text-sev-high">Rejected: {x.reject_reason}</div>}
      {x.error && <div className="text-sev-critical">Error: {x.error}</div>}
      {x.result && <JsonView value={x.result} collapsed />}
    </div>
  );
}

export function Timeline({ items, render }: { items: TimelineItem[]; render?: (i: TimelineItem) => ReactNode }) {
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const shown = useMemo(() => items.filter((i) => !hidden.has(i.kind)), [items, hidden]);
  const toggle = (k: string) => setHidden((h) => { const n = new Set(h); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-3 text-xs">
        {(Object.keys(KIND_LABEL) as (keyof typeof KIND_LABEL)[]).map((k) => (
          <label key={k} className="flex items-center gap-1"><input type="checkbox" checked={!hidden.has(k)} onChange={() => toggle(k)} />{KIND_LABEL[k]}</label>
        ))}
      </div>
      <ol className="relative space-y-3 border-l border-line pl-4">
        {shown.map((i) => (
          <li key={i.id} className="relative">
            <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[i.kind] }} aria-hidden="true" />
            <div className="mb-0.5 flex items-center gap-2 text-[11px] text-muted"><time className="mono">{fmtTime(i.ts)}</time><span className="uppercase tracking-wide">{KIND_LABEL[i.kind]}</span></div>
            {render?.(i) ?? <TimelineBody item={i} />}
          </li>
        ))}
        {!shown.length && <li className="text-muted">No events.</li>}
      </ol>
    </div>
  );
}

function TimelineBody({ item }: { item: TimelineItem }) {
  switch (item.kind) {
    case "anomaly": return <AnomalyBody a={item.data} />;
    case "review": return <ReviewBody r={item.data} />;
    case "action": return <ActionBody x={item.data} />;
    case "audit": return (
      <div className="space-y-1"><div><span className="mono font-semibold">{item.data.event}</span> <span className="text-muted">by {item.data.actor}</span></div>
        {item.data.detail != null && <JsonView value={item.data.detail} collapsed />}</div>
    );
  }
}
