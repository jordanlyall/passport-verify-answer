import { test } from "node:test";
import assert from "node:assert/strict";
import { ClaimError, decode, verifyAnswer } from "../index.js";

const enc = new TextEncoder();
const b64u = (bytes) => Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function keypair(kid) {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  return { priv: kp.privateKey, jwk: { kty: "EC", crv: "P-256", x: pub.x, y: pub.y, kid, alg: "ES256", use: "sig" } };
}

async function sign(payload, priv, kid, header = {}) {
  const h = b64u(enc.encode(JSON.stringify({ alg: "ES256", kid, typ: "passport-answer+jwt", ...header })));
  const p = b64u(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, enc.encode(h + "." + p));
  return `${h}.${p}.${b64u(sig)}`;
}

const NOW = 1_800_000_000;
const AUD = "https://tool.example/client";
const good = () => ({ iss: "passport", sub: "pairwise-sub", aud: AUD, iat: NOW, exp: NOW + 900, jti: "j1", q: "busy_times", a: "Busy 2-3", fact: "f" });

test("a claim signed by a key in the JWKS, for this audience, inside its window, verifies", async () => {
  const k = await keypair("srv-1");
  const claim = await sign(good(), k.priv, "srv-1");
  const out = await verifyAnswer(claim, { audience: AUD, jwks: { keys: [k.jwk] }, now: NOW * 1000 + 5000 });
  assert.deepEqual(out, { sub: "pairwise-sub", aud: AUD, q: "busy_times", a: "Busy 2-3", fact: "f", iat: NOW, exp: NOW + 900, jti: "j1", kid: "srv-1" });
  assert.equal(decode(claim).header.kid, "srv-1");
});

test("fetches the JWKS when given a URL", async () => {
  const k = await keypair("srv-2");
  const claim = await sign(good(), k.priv, "srv-2");
  const fetch = async (url) => ({ ok: true, json: async () => ({ keys: [k.jwk] }), url });
  const out = await verifyAnswer(claim, { audience: AUD, jwksUrl: "https://passport.test/.well-known/jwks.json", fetch, now: NOW * 1000 });
  assert.equal(out.kid, "srv-2");
});

test("refuses: another key, a tampered payload, a different audience, expired, future, wrong issuer, wrong typ/alg, unknown kid", async () => {
  const k = await keypair("srv-1");
  const other = await keypair("srv-1");
  const jwks = { keys: [k.jwk] };
  const at = NOW * 1000;
  const expect = async (claim, code, opts = {}) => {
    await assert.rejects(verifyAnswer(claim, { audience: AUD, jwks, now: at, ...opts }), (e) => e instanceof ClaimError && e.code === code, code);
  };
  await expect(await sign(good(), other.priv, "srv-1"), "bad_signature");
  const tampered = (await sign(good(), k.priv, "srv-1")).split(".");
  tampered[1] = b64u(enc.encode(JSON.stringify({ ...good(), a: "Free all day" })));
  await expect(tampered.join("."), "bad_signature");
  await expect(await sign(good(), k.priv, "srv-1"), "wrong_audience", { audience: "https://someone.else/client" });
  await expect(await sign({ ...good(), exp: NOW - 120 }, k.priv, "srv-1"), "expired");
  await expect(await sign({ ...good(), iat: NOW + 600, exp: NOW + 1500 }, k.priv, "srv-1"), "not_yet_valid");
  await expect(await sign({ ...good(), iss: "someone" }, k.priv, "srv-1"), "wrong_issuer");
  await expect(await sign(good(), k.priv, "srv-1", { typ: "JWT" }), "unsupported");
  await expect(await sign(good(), k.priv, "srv-1", { alg: "HS256" }), "unsupported");
  await expect(await sign(good(), k.priv, "srv-9"), "unknown_key");
  await expect("not.a.jws.at.all", "malformed");
  await expect(await sign({ ...good(), sub: 5 }, k.priv, "srv-1"), "malformed");
  // Skew: 30 s past exp is fine by default, 120 s is not.
  await verifyAnswer(await sign({ ...good(), exp: NOW - 30 }, k.priv, "srv-1"), { audience: AUD, jwks, now: at });
  await expect(await sign({ ...good(), exp: NOW - 30 }, k.priv, "srv-1"), "expired", { skewSeconds: 0 });
});

test("the audience is mandatory: no accidental verification for any client", async () => {
  const k = await keypair("srv-1");
  const claim = await sign(good(), k.priv, "srv-1");
  await assert.rejects(verifyAnswer(claim, { jwks: { keys: [k.jwk] } }), TypeError);
});
