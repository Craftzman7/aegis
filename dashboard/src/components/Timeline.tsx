import { useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { ActionRow, AgentTurn, AiReview, Anomaly, AuditEntry } from "../api/types";
import { fmtTime, short } from "../lib/format";
import { ConfidenceBar, Pill, SeverityBadge, StateBadge, VerdictBadge } from "./badges";
import { AttackTags, JsonView, KV } from "./ui";
import { ErrorBox } from "./ui";

export type TimelineItem =
  | { kind: "anomaly"; ts: string; id: string; data: Anomaly }
  | { kind: "review"; ts: string; id: string; data: AiReview }
  | { kind: "action"; ts: string; id: string; data: ActionRow }
  | { kind: "audit"; ts: string; id: string; data: AuditEntry }
  | { kind: "turn"; ts: string; id: string; data: AgentTurn };

export function buildTimeline(a: Anomaly[], r: AiReview[], x: ActionRow[], u: AuditEntry[], turns: AgentTurn[] = []): TimelineItem[] {
  const items: TimelineItem[] = [
    ...a.map((d): TimelineItem => ({ kind: "anomaly", ts: d.ts, id: `a${d.id}`, data: d })),
    ...r.map((d): TimelineItem => ({ kind: "review", ts: d.ts, id: `r${d.id}`, data: d })),
    ...x.map((d): TimelineItem => ({ kind: "action", ts: d.created_at, id: `x${d.id}`, data: d })),
    ...u.map((d): TimelineItem => ({ kind: "audit", ts: d.ts, id: `u${d.id}`, data: d })),
    ...turns.map((d): TimelineItem => ({ kind: "turn", ts: d.ts, id: `t${d.id}`, data: d })),
  ];
  return items.sort((p, q) => new Date(p.ts).getTime() - new Date(q.ts).getTime());
}

const KIND_LABEL = { anomaly: "Anomaly", review: "AI review", action: "Action", audit: "Audit", turn: "Agent turns" } as const;
const KIND_COLOR = { anomaly: "var(--sev-high)", review: "var(--accent)", action: "#2fa66a", audit: "var(--sev-info)", turn: "var(--muted)" } as const;

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
        <button type="button" className="text-xs text-muted hover:text-fg" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide evidence" : "Show evidence"}</button>
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

const clip = (t: string, n = 110) => (t.length > n ? `${t.slice(0, n)}...` : t);
const oneLine = (v: unknown) => clip((typeof v === "string" ? v : JSON.stringify(v) ?? "").replace(/\s+/g, " "));

/** One collapsed row: summary line, click to reveal the detail. */
function Row({ head, preview, tone, children }: { head: ReactNode; preview?: string; tone?: string; children?: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="px-2.5 py-1.5">
      <button type="button" className="flex w-full items-baseline gap-2 text-left" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="w-3 shrink-0 text-muted" aria-hidden="true">{open ? "\u25BE" : "\u25B8"}</span>
        <span className="shrink-0 font-medium">{head}</span>
        {preview && <span className={`mono min-w-0 flex-1 truncate ${tone ?? "text-muted"}`}>{preview}</span>}
      </button>
      {open && <div className="mt-1.5 pl-5">{children}</div>}
    </div>
  );
}

function TurnRows({ t }: { t: AgentTurn }) {
  const c = t.content;
  if (t.role === "tool") {
    const err = c.error != null;
    return (
      <Row head={<span className={err ? "text-sev-critical" : undefined}>{t.tool_name ?? "tool"} {err ? "error" : "result"}</span>} preview={err ? c.error : oneLine(c.result)} tone={err ? "text-sev-critical" : undefined}>
        {err ? <p className="mono whitespace-pre-wrap text-sev-critical">{c.error}</p> : <JsonView value={c.result} />}
      </Row>
    );
  }
  if (t.role === "user") return <Row head="Message to analyst" preview={oneLine(c.text ?? "")}><p className="whitespace-pre-wrap">{c.text}</p></Row>;
  return (
    <>
      {c.text && <p className="px-2.5 py-1.5 whitespace-pre-wrap">{c.text}</p>}
      {c.tool_calls?.map((tc) => (
        <Row key={tc.id} head={tc.name} preview={Object.entries(tc.arguments).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" ")}>
          <JsonView value={tc.arguments} />
        </Row>
      ))}
    </>
  );
}

/** Consecutive turns render as one bordered block so a 30-call investigation stays one scannable unit. */
function TurnGroup({ turns }: { turns: AgentTurn[] }) {
  const calls = turns.reduce((n, t) => n + (t.content.tool_calls?.length ?? 0), 0);
  return (
    <div className="rounded-lg border border-line bg-bg">
      <div className="label border-b border-line px-2.5 py-1">Investigation steps{calls ? ` \u00B7 ${calls} tool call${calls === 1 ? "" : "s"}` : ""}</div>
      <div className="divide-y divide-line">{turns.map((t) => <div key={t.id}><TurnRows t={t} /></div>)}</div>
    </div>
  );
}

type Entry = { key: string; ts: string; kind: TimelineItem["kind"]; item?: TimelineItem; turns?: AgentTurn[] };
function group(items: TimelineItem[]): Entry[] {
  const out: Entry[] = [];
  for (const i of items) {
    const last = out[out.length - 1];
    if (i.kind === "turn") {
      if (last?.turns) last.turns.push(i.data); else out.push({ key: i.id, ts: i.ts, kind: "turn", turns: [i.data] });
    } else out.push({ key: i.id, ts: i.ts, kind: i.kind, item: i });
  }
  return out;
}

export function Timeline({ items, render }: { items: TimelineItem[]; render?: (i: TimelineItem) => ReactNode }) {
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const shown = useMemo(() => group(items.filter((i) => !hidden.has(i.kind))), [items, hidden]);
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
          <li key={i.key} className="relative">
            <span className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full" style={{ background: KIND_COLOR[i.kind] }} aria-hidden="true" />
            <div className="mb-0.5 flex items-center gap-2 text-xs text-muted"><time className="mono">{fmtTime(i.ts)}</time><span className="first-letter:uppercase">{KIND_LABEL[i.kind]}</span></div>
            {i.turns ? <TurnGroup turns={i.turns} /> : i.item && (render?.(i.item) ?? <TimelineBody item={i.item} />)}
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
    case "turn": return null; // rendered by TurnGroup
  }
}
