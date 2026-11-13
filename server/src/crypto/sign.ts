import { b64dec, b64enc, sha256Hex, timingSafeEqual } from "../lib/util";
import type { SignedEnvelope } from "../types";

const ALG = { name: "Ed25519" } as const;
const MAX_SKEW_S = 300;

interface Loaded {
  priv: CryptoKey;
  pubRaw: Uint8Array;
}
const cache = new Map<string, Promise<Loaded>>();

/** Import the server signing key from the SIGNING_KEY_JWK secret (cached per isolate). */
export function loadSigningKey(jwkJson: string): Promise<Loaded> {
  let p = cache.get(jwkJson);
  if (!p) {
    p = (async () => {
      const jwk = JSON.parse(jwkJson) as JsonWebKey;
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.x) throw new Error("SIGNING_KEY_JWK must be an Ed25519 OKP JWK with d and x");
      const priv = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", d: jwk.d, x: jwk.x }, ALG, false, ["sign"]);
      return { priv, pubRaw: b64dec(jwk.x) };
    })();
    cache.set(jwkJson, p);
  }
  return p;
}

export async function serverPubkeyB64(jwkJson: string): Promise<string> {
  return b64enc((await loadSigningKey(jwkJson)).pubRaw);
}

/** Sign an object as an envelope: payload = base64(JSON bytes), sig = base64(sig over those exact bytes). */
export async function signEnvelope(jwkJson: string, obj: unknown): Promise<SignedEnvelope> {
  const { priv } = await loadSigningKey(jwkJson);
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  const sig = new Uint8Array(await crypto.subtle.sign(ALG, priv, bytes));
  return { payload: b64enc(bytes), sig: b64enc(sig) };
}

export async function verifyEnvelope(pubRaw: Uint8Array, env: SignedEnvelope): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", pubRaw, ALG, false, ["verify"]);
    return await crypto.subtle.verify(ALG, key, b64dec(env.sig), b64dec(env.payload));
  } catch {
    return false;
  }
}

/** canonical = METHOD \n PATH \n TS \n hex(sha256(body)) */
export async function canonicalString(method: string, path: string, ts: string | number, body: Uint8Array | string): Promise<string> {
  return `${method.toUpperCase()}\n${path}\n${ts}\n${await sha256Hex(body)}`;
}

export type AuthFailure = "bad_ts" | "skew" | "bad_sig";

/** Verify an agent request signature. Returns null when valid, else the failure reason. */
export async function verifyAgentRequest(args: {
  pubkeyB64: string;
  method: string;
  path: string;
  ts: string;
  sigB64: string;
  body: Uint8Array;
  nowS?: number;
}): Promise<AuthFailure | null> {
  if (!/^\d{1,12}$/.test(args.ts)) return "bad_ts";
  const now = args.nowS ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(args.ts)) > MAX_SKEW_S) return "skew";
  try {
    const pub = b64dec(args.pubkeyB64);
    if (pub.length !== 32) return "bad_sig";
    const key = await crypto.subtle.importKey("raw", pub, ALG, false, ["verify"]);
    const canonical = await canonicalString(args.method, args.path, args.ts, args.body);
    const ok = await crypto.subtle.verify(ALG, key, b64dec(args.sigB64), new TextEncoder().encode(canonical));
    return ok ? null : "bad_sig";
  } catch {
    return "bad_sig";
  }
}

export { sha256Hex, timingSafeEqual };
