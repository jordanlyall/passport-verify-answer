# passport-verify-answer

Passport is a remote MCP connector that answers narrow questions about a person ("busy 2-3pm?",
"vegetarian?", "has Netflix?") without handing over the underlying data. Every answer comes back
signed (ES256), so the tool that asked can check it instead of trusting whoever runs the server.

This package is that check. It confirms an answer really came from the connector, was issued to
your client, and is still fresh. Zero dependencies; WebCrypto only (Node 18+, browsers, Workers,
Deno, Bun).

```js
import { verifyAnswer } from "passport-verify-answer";

const result = await mcp.callTool("busy_times", { start: "2026-11-05", end: "2026-11-05" });
const claim = result._meta?.["passport/claim"];
const ok = await verifyAnswer(claim, {
  audience: MY_CLIENT_ID,                               // the OAuth client id you registered with
  jwksUrl: "https://<connector>/.well-known/jwks.json", // or jwks: { keys: [...] } you cached
});
// ok = { sub, aud, q: "busy_times", a: "<the answer text>", fact, iat, exp, jti, kid }
```

## What it checks

`alg` ES256 and `typ` `passport-answer+jwt`; the `kid` names a P-256 key in the JWKS; the
signature; `iss` is `passport`; `aud` equals your client id; `exp`/`iat` against now (60 s skew by
default). Otherwise it throws a `ClaimError` with a `code`: `malformed`, `unsupported`,
`unknown_key`, `bad_signature`, `expired`, `not_yet_valid`, `wrong_audience`, `wrong_issuer`.

The audience is mandatory, so a claim issued to another client never verifies for yours by
accident.

## What the payload means

- `sub`: a pairwise subject, stable for one user with your client and different for every other
  client. Safe to key your own records on, useless for matching with anyone else's.
- `q`: the tool that answered.
- `a`: the answer text, identical to the result's text.
- `fact`: an opaque, pairwise hash of the signed fact that answered, so you can tell whether two
  answers came from the same fact.

Every key the connector has ever signed with is also in its transparency log
(`/.well-known/passport-tools.json` → `transparency`), so a key you see in the JWKS can be checked
against an append-only record.

## Develop

```bash
npm test
```

MIT licensed.
