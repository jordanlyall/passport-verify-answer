export type ClaimErrorCode =
  | "malformed"
  | "unsupported"
  | "unknown_key"
  | "bad_signature"
  | "expired"
  | "not_yet_valid"
  | "wrong_audience"
  | "wrong_issuer";

export class ClaimError extends Error {
  code: ClaimErrorCode;
  constructor(code: ClaimErrorCode, message: string);
}

export interface VerifiedAnswer {
  /** Pairwise subject: stable for one user with your client, different for every other client. */
  sub: string;
  /** Your client id. */
  aud: string;
  /** The tool that answered, e.g. "busy_times". */
  q: string;
  /** The answer text, identical to the result's text. */
  a: string;
  /** Opaque, pairwise hash of the signed fact that answered. */
  fact: string;
  iat: number;
  exp: number;
  jti: string;
  kid: string;
}

export interface VerifyOptions {
  /** Your client id; the claim's aud must equal it. */
  audience: string;
  /** A JWKS document ({ keys: [...] }) you fetched or cached… */
  jwks?: { keys: Array<Record<string, unknown>> };
  /** …or where to fetch it: the connector's /.well-known/jwks.json. */
  jwksUrl?: string;
  now?: Date | number;
  skewSeconds?: number;
  fetch?: typeof fetch;
}

export function decode(claim: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
};

export function verifyAnswer(claim: string, opts: VerifyOptions): Promise<VerifiedAnswer>;
