import { useState } from "react";
import { useApprovals, useApprove, useReject } from "../api/hooks";
import type { Approval, JsonObject } from "../api/types";
import { Pill, SeverityBadge } from "../components/badges";
import { CodeEditor } from "../components/CodeEditor";
import { ConfirmDialog, Empty, ErrorBox, Field, HostLink, IncidentLink, KV, Loading, PageHeader } from "../components/ui";
import { TTL_ACTIONS, actionSpec, describeAction, validateParams } from "../lib/actions";
import { ago, asRecord, fmtTime, stringify } from "../lib/format";

type Mode = { kind: "approve" } | { kind: "ttl" } | { kind: "modify" } | { kind: "reject" };

function ApprovalCard({ a }: { a: Approval }) {
  const approve = useApprove();
  const reject = useReject();
  const [mode, setMode] = useState<Mode | null>(null);
  const [ttl, setTtl] = useState(String(a.params.ttl_seconds ?? 3600));
  const [json, setJson] = useState(stringify(a.params));
  const [reason, setReason] = useState("");
  const [formErr, setFormErr] = useState<string | null>(null);
  const hostname = a.host?.hostname ?? a.host_id.slice(0, 8);
  const spec = actionSpec(a.action);
  const close = () => { setMode(null); setFormErr(null); approve.reset(); reject.reset(); };

  let effParams: JsonObject = a.params;
  let effTtl: number | undefined;
  if (mode?.kind === "ttl") { effTtl = Number(ttl); effParams = { ...a.params, ttl_seconds: effTtl }; }
  if (mode?.kind === "modify") { try { effParams = asRecord(JSON.parse(json)); } catch { /* shown on submit */ } }

  const confirm = () => {
    setFormErr(null);
    if (mode?.kind === "reject") {
      if (!reason.trim()) { setFormErr("A reason is required; it is fed back to the AI."); return; }
      reject.mutate({ id: a.id, reason: reason.trim() }, { onSuccess: close });
      return;
    }
    let params: JsonObject | undefined;
    if (mode?.kind === "ttl") {
      const max = spec?.params.find((p) => p.name === "ttl_seconds")?.max ?? 86400;
      if (!Number.isInteger(effTtl) || (effTtl ?? 0) < 1 || (effTtl ?? 0) > max) { setFormErr(`TTL must be an integer between 1 and ${max} seconds.`); return; }
    }
    if (mode?.kind === "modify") {
      try { params = asRecord(JSON.parse(json)); } catch { setFormErr("Params are not valid JSON."); return; }
      if (spec) {
        const raw = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]));
        const r = validateParams(spec, raw);
        const first = Object.entries(r.errors)[0];
        if (first) { setFormErr(`${first[0]}: ${first[1]}`); return; }
      }
    }
    approve.mutate({ id: a.id, params, ttl_seconds: effTtl }, { onSuccess: close });
  };

  const verb = mode?.kind === "reject" ? "Reject" : "Approve";
  return (
    <section className="card p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[15px] font-medium first-letter:uppercase">{describeAction(a.action, a.params, hostname)}</h2>
          <p className="label mt-1">
            Proposed by {a.proposed_by === "ai" ? "the AI analyst" : a.proposed_by.replace(/^human:/, "")} {ago(a.created_at)}{a.expires_at ? ` · expires ${fmtTime(a.expires_at)}` : ""}
          </p>
        </div>
        {a.incident && <SeverityBadge severity={a.incident.severity} />}
      </div>
      <p className="mt-4 max-w-3xl whitespace-pre-wrap leading-relaxed">{a.rationale ?? "No rationale provided."}</p>
      {a.critic && (
        <div className="mt-4 max-w-3xl rounded-lg border border-line bg-bg p-3">
          <div className="flex items-center gap-2"><span className="label">Second-opinion review</span><Pill color={a.critic.decision === "submit" ? "var(--ok)" : "var(--sev-medium)"}>{a.critic.decision === "submit" ? "Supports the action" : "Asked for revision"}</Pill></div>
          {a.critic.concerns.length > 0 && <><p className="mt-2 font-medium">Concerns</p><ul className="list-disc pl-5">{a.critic.concerns.map((c, k) => <li key={k}>{c}</li>)}</ul></>}
          {a.critic.missing_checks.length > 0 && <><p className="mt-2 font-medium">Missing checks</p><ul className="list-disc pl-5">{a.critic.missing_checks.map((c, k) => <li key={k} className="mono">{c}</li>)}</ul></>}
        </div>
      )}
      <dl className="mt-4 grid gap-x-8 gap-y-3 sm:grid-cols-3">
        <div><dt className="label">Host</dt><dd className="mt-0.5"><HostLink id={a.host_id} name={hostname} /></dd></div>
        <div><dt className="label">Incident</dt><dd className="mt-0.5 truncate">{a.incident ? <IncidentLink id={a.incident.id} label={a.incident.title} /> : a.incident_id ? <IncidentLink id={a.incident_id} /> : "None"}</dd></div>
        <div><dt className="label">Parameters</dt><dd className="mt-0.5"><KV data={a.params} /></dd></div>
      </dl>
      <div className="mt-5 flex flex-wrap gap-2">
        <button type="button" className="btn btn-primary" onClick={() => setMode({ kind: "approve" })}>Approve</button>
        {TTL_ACTIONS.includes(a.action) && <button type="button" className="btn" onClick={() => setMode({ kind: "ttl" })}>Approve with TTL</button>}
        <button type="button" className="btn" onClick={() => setMode({ kind: "modify" })}>Modify params</button>
        <button type="button" className="btn" onClick={() => setMode({ kind: "reject" })}>Reject</button>
      </div>
      <ConfirmDialog open={mode !== null} danger={mode?.kind !== "reject" && (spec?.destructive ?? false)} busy={approve.isPending || reject.isPending}
        error={approve.error ?? reject.error ?? (formErr ? new Error(formErr) : null)} title={mode?.kind === "modify" ? "Modify params, then approve" : `${verb} ${a.action}`}
        confirmLabel={mode?.kind === "reject" ? "Reject action" : "Approve and execute"} onCancel={close} onConfirm={confirm}>
        {mode?.kind === "reject" ? (<>
          <p>The AI will be told this was rejected on <strong>{hostname}</strong>: <span className="mono">{a.action}</span>.</p>
          <Field label="Reason (required)"><textarea className="input" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
        </>) : (<>
          {mode?.kind === "ttl" && <Field label="TTL (seconds)"><input className="input mono" value={ttl} onChange={(e) => setTtl(e.target.value)} /></Field>}
          {mode?.kind === "modify" && <CodeEditor lang="json" label="Action params" height="160px" value={json} onChange={setJson} />}
          <p>This will <strong>{describeAction(a.action, effParams, hostname)}</strong>.</p>
          {spec?.destructive && <p className="text-sev-high">This is a live, disruptive change. It will be signed and dispatched to the agent immediately.</p>}
        </>)}
      </ConfirmDialog>
    </section>
  );
}

export function Approvals() {
  const q = useApprovals();
  return (
    <>
      <PageHeader title="Approvals" />
      {q.isLoading ? <Loading what="approvals" /> : q.error ? <ErrorBox error={q.error} /> : !q.data?.length ? <Empty>Nothing waiting for approval.</Empty> : (
        <div className="space-y-3">{q.data.map((a) => <ApprovalCard key={a.id} a={a} />)}</div>
      )}
    </>
  );
}
