import { useState } from "react";
import { api } from "../api/client";
import { errMsg } from "../lib/format";

interface Msg { role: "you" | "analyst" | "error"; text: string }

export function AskPanel({ incidentId }: { incidentId: string }) {
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    const question = q.trim();
    if (!question || busy) return;
    setQ(""); setBusy(true);
    setMsgs((m) => [...m, { role: "you", text: question }]);
    try {
      const r = await api.ask(incidentId, question);
      setMsgs((m) => [...m, { role: "analyst", text: r.answer }]);
    } catch (err) {
      setMsgs((m) => [...m, { role: "error", text: errMsg(err) }]);
    } finally { setBusy(false); }
  };
  return (
    <div className="space-y-2">
      <p className="rounded border border-line bg-panel2 px-2 py-1 text-[11px] text-muted">Read-only: the analyst can explain this incident but cannot run actions. Use the controls to respond.</p>
      <div className="max-h-72 space-y-2 overflow-auto" aria-live="polite">
        {msgs.map((m, i) => (
          <div key={i} className={`rounded p-2 ${m.role === "you" ? "bg-panel2" : m.role === "error" ? "border border-sev-critical text-sev-critical" : "border border-line"}`}>
            <div className="text-[11px] uppercase text-muted">{m.role === "you" ? "You" : m.role === "analyst" ? "AI analyst" : "Error"}</div>
            <div className="whitespace-pre-wrap">{m.text}</div>
          </div>
        ))}
        {busy && <div className="text-muted">Thinking...</div>}
      </div>
      <form onSubmit={(e) => void send(e)} className="flex gap-2">
        <input className="input flex-1" aria-label="Question for the analyst" placeholder="Why was this flagged as malicious?" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="btn btn-primary" disabled={busy || !q.trim()}>Ask</button>
      </form>
    </div>
  );
}
