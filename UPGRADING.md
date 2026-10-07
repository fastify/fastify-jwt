## Upgrading Notes
This document captures breaking changes between versions of `@fastify/jwt`.

### Upcoming major release

Function-based secrets now use the same `(context, callback)` signature in `fastify.jwt.sign()`, `fastify.jwt.verify()`, `reply.jwtSign()`, and `request.jwtVerify()`. Promise-returning providers receive the same context. Static secrets are unchanged.

- Replace the old `request` argument with `context.request`. It is only available in request/reply methods; instance methods have no request.
- Use `context.payload` for the payload and `context.operation` to distinguish `'sign'` from `'verify'`.
- During verification, `context.header` and `context.signature` are always available, regardless of `decode.complete`. They are absent during signing. Replace any conditional handling of the old token/header argument with these fields.
- Function-valued `sign.key` and `verify.key` overrides use the same context contract, not the native `fast-jwt` provider signature.
- Instance methods require a callback when the effective key is a function, including Promise-returning providers. A static per-call `key` override still permits synchronous calls. Request/reply methods still accept callbacks or return Promises.
- A provider that produces no usable key is no longer re-invoked under the native `fast-jwt` key fetcher contract. It now fails immediately with `FAST_JWT_KEY_FETCHING_ERROR` and runs exactly once, so an empty string or buffer that previously surfaced as a `401` from `request.jwtVerify()` is now reported as a `500`.
- In TypeScript, replace `TokenOrHeader` and native `fast-jwt.KeyFetcher` provider annotations with `SecretContext` and `SecretProvider`, respectively. Callback providers return `void`; Promise providers resolve to a string or buffer.

See the [secret option](README.md#secret-required) for examples. Verification contexts contain unverified input and must not be treated as authenticated data.

### Upgrading from 3.x to 4.0

In `v4` we migrated away from using `jsonwebtoken` to `fast-jwt`. This introduced the following breaking changes:
- **sign** options:
  - `audience` should be changed to `aud`
  - `issuer` should be changed to `iss`
  - `jwtid` should be changed to `jti`
  - `subject` should be changed to `sub`
  - `keyId` should be changed to `kid`

- **verify** options:
  - `audience` should be changed to `allowedAud`
  - `issuer` should be changed to `allowedIss`
  - `subject` should be changed to `allowedSub`
  - `jwtid` should be changed to `allowedJti`
  - `nonce` should be changed to `allowedNonce`

- **decode** options:
  - `json` option has been removed
  - `checkTyp` option has been introduced. If set to a string value, a check of the `typ` header claim is forced. Example: `checkTyp: 'JWT'`. By default `checkTyp` is `undefined`.
