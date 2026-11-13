import { describe, expect, it } from "vitest";
import { canonicalString, loadSigningKey, serverPubkeyB64, signEnvelope, verifyAgentRequest, verifyEnvelope } from "../src/crypto/sign";
import { b64dec, b64enc, fromHex, sha256Hex, timingSafeEqual } from "../src/lib/util";
import vector from "./fixtures/sign_vector.json";

async function keyFromSeed(seedHex: string) {
  const pkcs8 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...fromHex(seedHex)]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  return { priv, jwk };
}

describe("go cross-verification vector", () => {
  it("canonical string matches", async () => {
    expect(await canonicalString(vector.method, vector.path, vector.ts, vector.body)).toBe(vector.canonical);
  });
  it("derives the same pubkey and signature from the seed", async () => {
    const { priv, jwk } = await keyFromSeed(vector.seed_hex);
    expect(b64enc(b64dec(jwk.x!))).toBe(vector.public_key_b64);
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", priv, new TextEncoder().encode(vector.canonical)));
    expect(b64enc(sig)).toBe(vector.signature_b64);
  });
  it("verifies the Go signature as an agent request", async () => {
    const r = await verifyAgentRequest({ pubkeyB64: vector.public_key_b64, method: vector.method, path: vector.path, ts: String(vector.ts), sigB64: vector.signature_b64, body: new TextEncoder().encode(vector.body), nowS: vector.ts + 5 });
    expect(r).toBeNull();
  });
  it("rejects skew beyond 300s and tampered body/path", async () => {
    const base = { pubkeyB64: vector.public_key_b64, method: vector.method, path: vector.path, ts: String(vector.ts), sigB64: vector.signature_b64, body: new TextEncoder().encode(vector.body) };
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts + 301 })).toBe("skew");
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts - 301 })).toBe("skew");
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts, body: new TextEncoder().encode('{"anomalies":[1]}') })).toBe("bad_sig");
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts, path: "/v1/heartbeat" })).toBe("bad_sig");
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts, method: "GET" })).toBe("bad_sig");
    expect(await verifyAgentRequest({ ...base, nowS: vector.ts, ts: "abc" })).toBe("bad_ts");
  });
  it("server envelope format equals the Go vector (payload=b64(json), sig over raw json)", async () => {
    const { jwk } = await keyFromSeed(vector.seed_hex);
    const jwkJson = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x });
    const env = await signEnvelope(jwkJson, JSON.parse(vector.envelope_payload_json));
    expect(env.payload).toBe(vector.envelope_payload_b64);
    expect(env.sig).toBe(vector.envelope_sig_b64);
    expect(await verifyEnvelope(b64dec(vector.public_key_b64), { payload: vector.envelope_payload_b64, sig: vector.envelope_sig_b64 })).toBe(true);
    expect(await serverPubkeyB64(jwkJson)).toBe(vector.public_key_b64);
  });
});

describe("helpers", () => {
  it("sha256 and timing-safe compare", async () => {
    expect(await sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
  });
  it("rejects malformed signing key", async () => {
    await expect(loadSigningKey('{"kty":"RSA"}')).rejects.toThrow();
  });
});
