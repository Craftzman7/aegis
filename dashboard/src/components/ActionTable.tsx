import { useState } from "react";
import { useRollback } from "../api/hooks";
import type { ActionRow } from "../api/types";
import { fmtTime } from "../lib/format";
import { StateBadge } from "./badges";
import { ConfirmDialog, Empty, IncidentLink, KV } from "./ui";

export function ActionTable({ actions, hostname }: { actions: ActionRow[]; hostname: string }) {
  const rb = useRollback();
  const [target, setTarget] = useState<ActionRow | null>(null);
  if (!actions.length) return <Empty>No actions.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="tbl">
        <thead><tr><th>Time</th><th>Action</th><th>Params</th><th>State</th><th>By</th><th>Incident</th><th /></tr></thead>
        <tbody>
          {actions.map((a) => (
            <tr key={a.id}>
              <td className="mono whitespace-nowrap">{fmtTime(a.created_at)}</td>
              <td className="mono font-semibold">{a.action}</td>
              <td><KV data={a.params} /></td>
              <td><StateBadge state={a.state} /></td>
              <td className="mono">{a.proposed_by}{a.approved_by ? ` / ok: ${a.approved_by}` : ""}</td>
              <td>{a.incident_id ? <IncidentLink id={a.incident_id} /> : "-"}</td>
              <td>{a.rollback_token && a.state === "succeeded" && <button type="button" className="btn" onClick={() => setTarget(a)}>Rollback</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ConfirmDialog open={target !== null} title="Roll back action" confirmLabel="Roll back" danger busy={rb.isPending} error={rb.error}
        onCancel={() => { setTarget(null); rb.reset(); }} onConfirm={() => target && rb.mutate(target.id, { onSuccess: () => setTarget(null) })}>
        <p>This will undo <strong className="mono">{target?.action}</strong> on host <strong>{hostname}</strong>, restoring the prior state.</p>
      </ConfirmDialog>
    </div>
  );
}
