## Upgrading Notes
This document captures breaking changes between versions of `@fastify/jwt`.

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
