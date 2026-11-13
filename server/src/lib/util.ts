export const nowIso = (): string => new Date().toISOString();

export function b64enc(bytes: Uint8Array): string {
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode(...bytes.subarray(i, i + CH));
  return btoa(s);
}

export function b64dec(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error("bad hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** Constant-time string/bytes comparison (length leak only). */
export function timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const enc = new TextEncoder();
  const x = typeof a === "string" ? enc.encode(a) : a;
  const y = typeof b === "string" ? enc.encode(b) : b;
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i % (x.length || 1)] ?? 0) ^ (y[i % (y.length || 1)] ?? 0);
  return diff === 0;
}

export function randomToken(bytes = 24): string {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** UUIDv4-shaped id derived from a seed, so workflow steps can create rows idempotently. */
export async function deterministicUuid(seed: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(seed))).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x40;
  h[8] = (h[8]! & 0x3f) | 0x80;
  const x = toHex(h);
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function safeJson<T>(s: string | null | undefined, fallback: T): T {
  if (s == null || s === "") return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

/** Convert a D1 row: parse `*_json` columns into objects under the key without the suffix. */
export function parseRow(row: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (k.endsWith("_json")) out[k.slice(0, -5)] = typeof v === "string" ? safeJson(v, null) : v;
    else out[k] = v;
  }
  return out;
}

export const parseRows = (rows: object[]) => rows.map(parseRow);

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max) + `…[truncated ${s.length - max} chars]`;
}

export function placeholders(n: number): string {
  return Array.from({ length: n }, () => "?").join(",");
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function log(message: string, extra: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ message, ...extra }));
}

export function logError(message: string, e: unknown, extra: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ message, error: errMsg(e), ...extra }));
}
