import { useRef, useState } from "react";
import { api } from "../api/client";
import { useGlobalAutonomy, useMe, useSetAutonomy } from "../api/hooks";
import type { AutonomyMode } from "../api/types";
import { Card, ConfirmDialog, CopyButton, ErrorBox, Field, PageHeader } from "../components/ui";
import { errMsg, fmtTime } from "../lib/format";

const MODES: { id: AutonomyMode; label: string; desc: string }[] = [
  { id: "autonomous", label: "Autonomous", desc: "The AI executes tier-0 (safe, reversible) actions on its own. Tier-1 actions (kill, block, isolate, disable user, quarantine) always wait for a human." },
  { id: "propose_only", label: "Propose only", desc: "The AI still investigates but every action, even tier-0, is queued for approval." },
  { id: "paused", label: "Paused", desc: "AI triage is off. Anomalies are only collected and queued; nothing is analysed or proposed." },
];

function Autonomy() {
  const q = useGlobalAutonomy();
  const set = useSetAutonomy();
  const [pending, setPending] = useState<AutonomyMode | null>(null);
  return (
    <Card title="Global autonomy">
      <div role="radiogroup" aria-label="Global autonomy mode" className="space-y-2">
        {MODES.map((m) => (
          <label key={m.id} className={`flex cursor-pointer gap-3 rounded border p-2 ${q.data?.mode === m.id ? "border-accent bg-panel2" : "border-line"}`}>
            <input type="radio" name="autonomy" checked={q.data?.mode === m.id} onChange={() => setPending(m.id)} />
            <span><span className="font-semibold">{m.label}</span><span className="block text-muted">{m.desc}</span></span>
          </label>
        ))}
      </div>
      <p className="mt-2 text-xs text-muted">Per-host overrides on the host page take precedence over this setting.</p>
      <ConfirmDialog open={pending !== null} title="Change global autonomy" busy={set.isPending} error={set.error} danger={pending === "paused"}
        onCancel={() => { setPending(null); set.reset(); }} onConfirm={() => pending && set.mutate(pending, { onSuccess: () => setPending(null) })}>
        <p>Set AI autonomy for the whole fleet to <strong>{MODES.find((m) => m.id === pending)?.label}</strong>?</p>
        <p className="text-muted">{MODES.find((m) => m.id === pending)?.desc}</p>
      </ConfirmDialog>
    </Card>
  );
}

function Enrollment() {
  const [ttl, setTtl] = useState("24");
  const [res, setRes] = useState<{ token: string; expires_at: string } | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const origin = location.origin;
  const gen = async () => {
    setErr(null);
    const h = Number(ttl);
    if (!Number.isInteger(h) || h < 1 || h > 168) { setErr(new Error("TTL must be 1 to 168 hours.")); return; }
    try { setRes(await api.createEnrollToken(h)); } catch (e) { setErr(e); }
  };
  const curl = res ? `curl -fsSL ${origin}/install.sh | sudo sh -s -- --token ${res.token} --server ${origin}` : "";
  const alt = res ? `aegis-agent enroll --server ${origin} --token ${res.token}` : "";
  return (
    <Card title="Enrollment token">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Valid for (hours)"><input className="input w-24 mono" value={ttl} onChange={(e) => setTtl(e.target.value)} /></Field>
        <button type="button" className="btn btn-primary" onClick={() => void gen()}>Generate token</button>
      </div>
      {err != null && <div className="mt-2"><ErrorBox error={err} /></div>}
      {res && (
        <div className="mt-3 space-y-3">
          <p role="status" className="text-sev-medium">This token is shown only once. It expires {fmtTime(res.expires_at)} and works for a single enrollment.</p>
          {[["Token", res.token], ["Install", curl], ["Alternative", alt]].map(([l, t]) => (
            <div key={l}><div className="label mb-1">{l}</div>
              <div className="flex items-start gap-2"><code className="mono flex-1 break-all rounded border border-line bg-bg p-2">{t}</code><CopyButton text={t} /></div></div>
          ))}
        </div>
      )}
    </Card>
  );
}

function Iocs() {
  const file = useRef<HTMLInputElement>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const upload = async () => {
    const f = file.current?.files?.[0];
    if (!f) { setMsg({ ok: false, text: "Choose a file first." }); return; }
    const text = await f.text();
    const isJson = f.name.toLowerCase().endsWith(".json") || text.trimStart().startsWith("{");
    try {
      const r = await api.importIocs(text, isJson ? "application/json" : "text/csv");
      setMsg({ ok: true, text: `Imported${r.imported != null ? ` ${r.imported} indicators` : ""}.` });
    } catch (e) { setMsg({ ok: false, text: errMsg(e) }); }
  };
  return (
    <Card title="Indicators of compromise">
      <div className="space-y-2">
        <Field label="STIX 2.x bundle (.json) or CSV with header type,value (types: ip, sha256, domain)">
          <input ref={file} type="file" accept=".json,.csv,application/json,text/csv" className="input" />
        </Field>
        <div className="flex items-center gap-2">
          <button type="button" className="btn btn-primary" onClick={() => void upload()}>Import</button>
          <a className="btn" href={api.stixUrl()} download>Export STIX</a>
        </div>
        {msg && <p role="status" className={msg.ok ? "text-[#2fa66a]" : "text-sev-critical"}>{msg.text}</p>}
      </div>
    </Card>
  );
}

export function Settings() {
  const me = useMe();
  return (
    <>
      <PageHeader title="Settings" />
      <div className="grid max-w-4xl gap-4">
        <Card title="Current user"><span className="mono">{me.data?.email ?? "..."}</span></Card>
        <Autonomy />
        <Enrollment />
        <Iocs />
      </div>
    </>
  );
}
