import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { useHosts, useIncident, useVerdict } from "../api/hooks";
import { ConfidenceBar, SeverityBadge, StateBadge, VerdictBadge } from "../components/badges";
import { AskPanel } from "../components/AskPanel";
import { ManualActionForm } from "../components/ManualAction";
import { buildTimeline, Timeline } from "../components/Timeline";
import { AttackTags, Card, ConfirmDialog, Empty, ErrorBox, Field, HostLink, Loading, PageHeader } from "../components/ui";
import { fmtTime } from "../lib/format";

export function IncidentDetail() {
  const { id = "" } = useParams();
  const q = useIncident(id);
  const hosts = useHosts();
  const verdict = useVerdict();
  const [pending, setPending] = useState<"true_positive" | "false_positive" | null>(null);
  const [note, setNote] = useState("");
  const timeline = useMemo(() => q.data ? buildTimeline(q.data.anomalies, q.data.reviews.filter((r) => r.step !== "ask"), q.data.actions, q.data.audit) : [], [q.data]);
  if (q.isLoading) return <Loading what="incident" />;
  if (q.error || !q.data) return <ErrorBox error={q.error} />;
  const { incident: i } = q.data;
  const host = q.data.host ?? hosts.data?.find((h) => h.id === i.host_id) ?? null;
  const closed = i.status === "closed_benign" || i.status === "closed_tp";
  return (
    <>
      <PageHeader title={i.title}>
        <a className="btn" href={api.ocsfUrl(i.id)} download>Export OCSF</a>
      </PageHeader>
      <div className="-mt-3 mb-6 flex flex-wrap items-center gap-x-5 gap-y-2 text-muted">
        <SeverityBadge severity={i.severity} />
        <StateBadge state={i.status} />
        <VerdictBadge verdict={i.verdict} />
        <span className="flex items-center gap-2">Confidence <ConfidenceBar value={i.confidence} /></span>
        <span>on <HostLink id={i.host_id} name={host?.hostname} /></span>
        <span>opened {fmtTime(i.created_at)}</span>
        <AttackTags tags={i.attack_tags} />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Card title="AI summary">{i.ai_summary ? <p className="whitespace-pre-wrap">{i.ai_summary}</p> : <Empty>No summary yet.</Empty>}
            {i.analyst_note && <p className="mt-2 border-t border-line pt-2"><span className="text-muted">Analyst note: </span>{i.analyst_note}</p>}</Card>
          <Card title="Timeline"><Timeline items={timeline} /></Card>
        </div>
        <div className="space-y-4">
          <Card title="Verdict">
            <div className="flex gap-2">
              <button type="button" className="btn" disabled={closed} onClick={() => setPending("true_positive")}>Mark True Positive</button>
              <button type="button" className="btn" disabled={closed} onClick={() => setPending("false_positive")}>Mark False Positive</button>
            </div>
            {closed && <p className="mt-2 text-muted">Incident is closed.</p>}
          </Card>
          <Card title="Ask the analyst (read-only)"><AskPanel incidentId={i.id} /></Card>
          <Card title="Manual response">{host ? <ManualActionForm host={host} incidentId={i.id} /> : <Loading what="host" />}</Card>
        </div>
      </div>
      <ConfirmDialog open={pending !== null} title={pending === "true_positive" ? "Mark as True Positive" : "Mark as False Positive"} busy={verdict.isPending} error={verdict.error}
        confirmLabel="Save verdict" onCancel={() => { setPending(null); verdict.reset(); }}
        onConfirm={() => pending && verdict.mutate({ id: i.id, verdict: pending, note }, { onSuccess: () => { setPending(null); setNote(""); } })}>
        <p>This closes the investigation and feeds the label back into the AI's memory{pending === "false_positive" ? " (suppression suggestions may follow)" : ""}.</p>
        <Field label="Note"><textarea className="input" rows={3} value={note} onChange={(e) => setNote(e.target.value)} /></Field>
      </ConfirmDialog>
    </>
  );
}
