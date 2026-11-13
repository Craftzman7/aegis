import { useState } from "react";
import { useManualAction } from "../api/hooks";
import type { Host, JsonObject } from "../api/types";
import { MANUAL_ACTIONS, actionSpec, describeAction, validateParams, type FormValues } from "../lib/actions";
import { ConfirmDialog, ErrorBox, Field } from "./ui";

/** Manual response form: action dropdown, per-action param fields, client-side bound validation, confirm. */
export function ManualActionForm({ host, incidentId }: { host: Host; incidentId?: string }) {
  const [name, setName] = useState(MANUAL_ACTIONS[0].name);
  const [vals, setVals] = useState<FormValues>({});
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [pending, setPending] = useState<JsonObject | null>(null);
  const [ok, setOk] = useState(false);
  const m = useManualAction();
  const spec = actionSpec(name) ?? MANUAL_ACTIONS[0];

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setOk(false);
    const r = validateParams(spec, vals);
    setErrors(r.errors);
    if (Object.keys(r.errors).length === 0) setPending(r.params);
  };
  return (
    <form onSubmit={submit} className="space-y-3" noValidate>
      <Field label="Action">
        <select className="input" value={name} onChange={(e) => { setName(e.target.value as typeof name); setVals({}); setErrors({}); setOk(false); }}>
          {MANUAL_ACTIONS.map((a) => <option key={a.name} value={a.name}>{a.label} ({a.name}){a.tier ? " - tier 1" : ""}</option>)}
        </select>
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        {spec.params.map((p) => (
          <Field key={p.name} label={p.label + (p.required ? " *" : "")} error={errors[p.name]} hint={p.hint}>
            {p.kind === "select" ? (
              <select className="input" value={vals[p.name] ?? ""} onChange={(e) => setVals({ ...vals, [p.name]: e.target.value })}>
                <option value="">Select...</option>{p.options?.map((o) => <option key={o}>{o}</option>)}
              </select>
            ) : (
              <input className="input mono" inputMode={p.kind === "int" ? "numeric" : undefined} placeholder={p.placeholder} value={vals[p.name] ?? ""}
                onChange={(e) => setVals({ ...vals, [p.name]: e.target.value })} />
            )}
          </Field>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <button type="submit" className={`btn ${spec.destructive ? "btn-danger" : "btn-primary"}`}>Execute on {host.hostname}</button>
        {ok && <span className="text-xs text-[#2fa66a]" role="status">Action submitted.</span>}
      </div>
      <p className="text-xs text-muted">Manual actions are issued as you, go through the same bounds checks and signing path, and ignore the approval tier.</p>
      <ConfirmDialog open={pending !== null} danger={spec.destructive} busy={m.isPending} error={m.error} title={`Confirm: ${spec.label}`} confirmLabel="Execute"
        onCancel={() => { setPending(null); m.reset(); }}
        onConfirm={() => pending && m.mutate({ host_id: host.id, action: spec.name, params: pending, incident_id: incidentId }, { onSuccess: () => { setPending(null); setOk(true); setVals({}); } })}>
        <p>This will <strong>{pending ? describeAction(spec.name, pending, host.hostname) : ""}</strong>.</p>
        {spec.destructive && <p className="text-sev-high">This changes the live system and may disrupt services.</p>}
      </ConfirmDialog>
      {m.error && !pending && <ErrorBox error={m.error} />}
    </form>
  );
}
