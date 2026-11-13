#!/usr/bin/env node
// Prints an Ed25519 JWK suitable for .dev.vars (or `wrangler secret put SIGNING_KEY_JWK`).
import { webcrypto as crypto } from "node:crypto";

const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
const compact = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x });
const pub = Buffer.from(jwk.x.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("base64");
console.error(`# server_pubkey (what agents pin): ${pub}`);
console.error("# Paste the next line into server/.dev.vars, or: echo '<json>' | wrangler secret put SIGNING_KEY_JWK");
console.log(`SIGNING_KEY_JWK='${compact}'`);
