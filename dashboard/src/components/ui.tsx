import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errMsg, stringify, techniqueId, techniqueUrl, short } from "../lib/format";

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-2 px-4 pt-3.5">
          <h2 className="text-sm font-medium">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
export function PageHeader({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  );
}
export const Loading = ({ what = "data" }: { what?: string }) => <div className="p-4 text-muted" role="status">Loading {what}...</div>;
export const Empty = ({ children }: { children: ReactNode }) => <div className="p-4 text-center text-muted">{children}</div>;
export function ErrorBox({ error }: { error: unknown }) {
  return <div role="alert" className="rounded-lg bg-sev-critical/10 px-3 py-2.5 text-sev-critical">{errMsg(error)}</div>;
}
export function Field({ label, error, hint, children }: { label: string; error?: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="font-medium text-muted">{label}</span>
      {children}
      {hint && !error && <span className="text-xs text-muted">{hint}</span>}
      {error && <span role="alert" className="text-xs text-sev-critical">{error}</span>}
    </label>
  );
}

export function AttackTags({ tags }: { tags: string[] }) {
  if (!tags.length) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {tags.map((t) => {
        const id = techniqueId(t);
        return id ? (
          <a key={t} href={techniqueUrl(id)} target="_blank" rel="noreferrer" className="mono rounded-md bg-panel2 px-1.5 py-0.5 text-muted hover:text-fg">{id}</a>
        ) : (
          <span key={t} className="rounded-md bg-panel2 px-1.5 py-0.5 text-xs text-muted">{t.replace(/^attack\./, "")}</span>
        );
      })}
    </span>
  );
}

export const HostLink = ({ id, name }: { id: string; name?: string }) => <Link className="font-medium hover:underline" to={`/hosts/${id}`}>{name ?? short(id)}</Link>;
export const IncidentLink = ({ id, label }: { id: string; label?: string }) => <Link className="font-medium hover:underline" to={`/incidents/${id}`}>{label ?? short(id)}</Link>;

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="btn" onClick={() => { void navigator.clipboard?.writeText(text).then(() => { setDone(true); window.setTimeout(() => setDone(false), 1500); }); }}>
      {done ? "Copied" : label}
    </button>
  );
}

/** Collapsible, pretty-printed JSON in a monospace block. */
export function JsonView({ value, collapsed = false, maxHeight = 320 }: { value: unknown; collapsed?: boolean; maxHeight?: number }) {
  const [open, setOpen] = useState(!collapsed);
  const text = stringify(value);
  return (
    <div className="rounded-lg border border-line bg-bg">
      <div className="flex items-center justify-between border-b border-line px-2.5 py-1">
        <button type="button" className="text-xs text-muted hover:text-fg" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide" : "Show"} JSON</button>
        <CopyButton text={text} />
      </div>
      {open && <pre className="mono overflow-auto p-2 whitespace-pre-wrap break-all" style={{ maxHeight }}>{text}</pre>}
    </div>
  );
}

export function KV({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data);
  if (!entries.length) return <span className="text-muted">none</span>;
  return (
    <dl className="mono grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5">
      {entries.map(([k, v]) => (
        <div key={k} className="contents"><dt className="text-muted">{k}</dt><dd className="break-all">{typeof v === "string" ? v : JSON.stringify(v)}</dd></div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="tablist" className="mb-3 flex gap-1 border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} type="button" onClick={() => onChange(t.id)}
          className={`-mb-px px-3 py-2 text-sm ${value === t.id ? "border-b-2 border-fg font-medium text-fg" : "text-muted hover:text-fg"}`}>{t.label}</button>
      ))}
    </div>
  );
}

export interface ConfirmProps {
  open: boolean; title: string; children: ReactNode; confirmLabel?: string; danger?: boolean;
  busy?: boolean; error?: unknown; onConfirm: () => void; onCancel: () => void;
}
export function ConfirmDialog({ open, title, children, confirmLabel = "Confirm", danger, busy, error, onConfirm, onCancel }: ConfirmProps) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
      if (e.key === "Tab" && ref.current) {
        const f = ref.current.querySelectorAll<HTMLElement>("button, input, textarea, select, a[href]");
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus(); };
  }, [open, onCancel]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-[2px]" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}>
      <div ref={ref} role="alertdialog" aria-modal="true" aria-label={title} className="card w-full max-w-lg p-5 shadow-2xl">
        <h2 className="mb-2 text-base font-semibold">{title}</h2>
        <div className="mb-4 space-y-2">{children}</div>
        {error != null && <div className="mb-3"><ErrorBox error={error} /></div>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" data-autofocus className={`btn ${danger ? "btn-danger" : "btn-primary"}`} onClick={onConfirm} disabled={busy}>{busy ? "Working..." : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
