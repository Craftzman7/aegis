export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { hour12: false });
}
export function fmtClock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString(undefined, { hour12: false });
}
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const OFFLINE_AFTER_MS = 2 * 60 * 1000;
export function isOffline(lastSeen: string | null | undefined, now = Date.now()): boolean {
  return !lastSeen || now - new Date(lastSeen).getTime() > OFFLINE_AFTER_MS;
}
export const short = (id: string) => id.slice(0, 8);
export const pct = (n: number | null | undefined) => (n == null ? "-" : `${Math.round(n * 100)}%`);
export function stringify(v: unknown): string {
  return JSON.stringify(v, null, 2) ?? "null";
}
/** Normalizes "attack.t1059.004" / "T1059.004" to "T1059.004"; returns null for tactic tags. */
export function techniqueId(tag: string): string | null {
  const m = /^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$/i.exec(tag);
  return m ? m[1].toUpperCase() : null;
}
export function techniqueUrl(id: string): string {
  const [a, b] = id.split(".");
  return `https://attack.mitre.org/techniques/${a}${b ? `/${b}` : ""}/`;
}
export function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
