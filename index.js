// Verify a Passport answer claim. Zero dependencies; runs anywhere WebCrypto does (Node 18+,
// browsers, Workers, Deno, Bun).
//
// An answered tool result carries `_meta["passport/claim"]`: a compact JWS (ES256, typ
// "passport-answer+jwt") whose payload is
//   { iss: "passport", sub, aud, iat, exp, jti, q, a, fact }
//   sub   pairwise subject for this client (stable per user × client, different per client)
//   aud   the client id the answer was issued to (your OAuth client id)
//   q     the tool that answered, e.g. "busy_times"
//   a     the answer text, exactly as the result's text
//   fact  SHA-256 over the client id and the signed fact that answered (opaque; stable per fact)
// Keys come from the connector's /.well-known/jwks.json; the key id (`kid`) in the JWS header
// names the one to use. Every key ever used is also in the connector's transparency log.

const enc = new TextEncoder();
const dec = new TextDecoder();

export class ClaimError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ClaimError";
    this.code = code;
  }
}

function b64uToBytes(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new ClaimError("malformed", "not base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Parse without verifying. Use it to find the kid; never trust its payload before verify(). */
export function decode(claim) {
  if (typeof claim !== "string") throw new ClaimError("malformed", "claim must be a string");
  const parts = claim.split(".");
  if (parts.length !== 3) throw new ClaimError("malformed", "expected three dot-separated parts");
  let header, payload;
  try {
    header = JSON.parse(dec.decode(b64uToBytes(parts[0])));
    payload = JSON.parse(dec.decode(b64uToBytes(parts[1])));
  } catch (e) {
    if (e instanceof ClaimError) throw e;
    throw new ClaimError("malformed", "header or payload is not JSON");
  }
  return { header, payload, signingInput: parts[0] + "." + parts[1], signature: b64uToBytes(parts[2]) };
}

/**
 * Verify a claim.
 * @param {string} claim  the JWS from _meta["passport/claim"]
 * @param {object} opts
 * @param {string} opts.audience   your client id; the claim's aud must equal it
 * @param {{keys: object[]}} [opts.jwks]   a JWKS document, or
 * @param {string} [opts.jwksUrl]          where to fetch it (the connector's /.well-known/jwks.json)
 * @param {Date|number} [opts.now]         for tests; defaults to the current time
 * @param {number} [opts.skewSeconds=60]   tolerance on iat/exp
 * @param {typeof fetch} [opts.fetch]
 * @returns {Promise<{ sub: string, aud: string, q: string, a: string, fact: string, iat: number, exp: number, jti: string, kid: string }>}
 * @throws {ClaimError} with code: malformed | unsupported | unknown_key | bad_signature | expired | not_yet_valid | wrong_audience | wrong_issuer
 */
export async function verifyAnswer(claim, opts) {
  if (!opts || typeof opts.audience !== "string" || !opts.audience) throw new TypeError("opts.audience (your client id) is required");
  const { header, payload, signingInput, signature } = decode(claim);
  if (header.alg !== "ES256" || header.typ !== "passport-answer+jwt") throw new ClaimError("unsupported", `alg ${header.alg}, typ ${header.typ}`);
  if (typeof header.kid !== "string") throw new ClaimError("malformed", "no kid");

  const jwks = opts.jwks ?? (await fetchJwks(opts.jwksUrl, opts.fetch));
  const jwk = (jwks.keys ?? []).find((k) => k.kid === header.kid && k.kty === "EC" && k.crv === "P-256");
  if (!jwk) throw new ClaimError("unknown_key", `no P-256 key with kid ${header.kid} in the JWKS`);
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, enc.encode(signingInput));
  if (!ok) throw new ClaimError("bad_signature", "signature does not verify");

  const now = Math.floor((opts.now instanceof Date ? opts.now.getTime() : typeof opts.now === "number" ? opts.now : Date.now()) / 1000);
  const skew = opts.skewSeconds ?? 60;
  for (const f of ["sub", "aud", "jti", "q", "a", "fact"]) if (typeof payload[f] !== "string") throw new ClaimError("malformed", `missing ${f}`);
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) throw new ClaimError("malformed", "iat/exp must be integers");
  if (payload.iss !== "passport") throw new ClaimError("wrong_issuer", `iss ${payload.iss}`);
  if (payload.aud !== opts.audience) throw new ClaimError("wrong_audience", "this claim was issued to a different client");
  if (payload.exp + skew < now) throw new ClaimError("expired", "claim has expired");
  if (payload.iat - skew > now) throw new ClaimError("not_yet_valid", "claim is from the future");

  const { sub, aud, q, a, fact, iat, exp, jti } = payload;
  return { sub, aud, q, a, fact, iat, exp, jti, kid: header.kid };
}

async function fetchJwks(url, f = globalThis.fetch) {
  if (!url) throw new TypeError("opts.jwks or opts.jwksUrl is required");
  const res = await f(url);
  if (!res.ok) throw new ClaimError("unknown_key", `JWKS fetch failed: ${res.status}`);
  return res.json();
}
