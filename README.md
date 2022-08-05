# @fastify/jwt

![CI](https://github.com/fastify/fastify-jwt/workflows/CI/badge.svg)
[![NPM version](https://img.shields.io/npm/v/@fastify/jwt.svg?style=flat)](https://www.npmjs.com/package/@fastify/jwt)
[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](https://standardjs.com/)

JWT utils for Fastify, internally it uses [fast-jwt](https://github.com/nearform/fast-jwt).

**NOTE:** The plugin has been migrated from using `jsonwebtoken` to `fast-jwt`. Even though `fast-jwt` has 1:1 feature implementation with `jsonwebtoken`, some _exotic_ implementations might break. In that case please open an issue with details of your implementation. See [Upgrading notes](UPGRADING.md) for more details about what changes this migration introduced.

`@fastify/jwt` supports Fastify@3.
`@fastify/jwt` [v1.x](https://github.com/fastify/fastify-jwt/tree/1.x)
supports both Fastify@2.

## Install
```
npm i @fastify/jwt
```

## Usage
Register as a plugin. This will decorate your `fastify` instance with the following methods: `decode`, `sign`, and `verify`; refer to their documentation to find how to use the utilities. It will also register `request.jwtVerify` and `reply.jwtSign`. You must pass a `secret` when registering the plugin.

```js
const fastify = require('fastify')()
fastify.register(require('@fastify/jwt'), {
  secret: 'supersecret'
})

fastify.post('/signup', (req, reply) => {
  // some code
  const token = fastify.jwt.sign({ payload })
  reply.send({ token })
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```

For verifying & accessing the decoded token inside your services, you can use a global `onRequest` hook to define the verification process like so:

```js
const fastify = require('fastify')()
fastify.register(require('@fastify/jwt'), {
  secret: 'supersecret'
})

fastify.addHook("onRequest", async (request, reply) => {
  try {
    await request.jwtVerify()
  } catch (err) {
    reply.send(err)
  }
})
```

Afterwards, just use `request.user` in order to retrieve the user information:

```js
module.exports = async function(fastify, opts) {
  fastify.get("/", async function(request, reply) {
    return request.user
  })
}
```

However, most of the time we want to protect only some of the routes in our application. To achieve this you can wrap your authentication logic into a plugin like

```js
const fp = require("fastify-plugin")

module.exports = fp(async function(fastify, opts) {
  fastify.register(require("@fastify/jwt"), {
    secret: "supersecret"
  })

  fastify.decorate("authenticate", async function(request, reply) {
    try {
      await request.jwtVerify()
    } catch (err) {
      reply.send(err)
    }
  })
})
```

Then use the `onRequest` of a route to protect it & access the user information inside:

```js
module.exports = async function(fastify, opts) {
  fastify.get(
    "/",
    {
      onRequest: [fastify.authenticate]
    },
    async function(request, reply) {
      return request.user
    }
  )
}
```

Make sure that you also check [@fastify/auth](https://github.com/fastify/fastify-auth) plugin for composing more complex strategies.

### Auth0 tokens verification

If you need to verify Auth0 issued HS256 or RS256 JWT tokens, you can use [fastify-auth0-verify](https://github.com/nearform/fastify-auth0-verify), which is based on top of this module.

## Options

### `secret` (required)
You must pass a `secret` to the `options` parameter. The `secret` can be a primitive type String, a function that returns a String or an object `{ private, public }`.

In this object `{ private, public }` the `private` key is a string, buffer or object containing either the secret for HMAC algorithms or the PEM encoded private key for RSA and ECDSA. In case of a private key with passphrase an object `{ private: { key, passphrase }, public }` can be used (based on [crypto documentation](https://nodejs.org/api/crypto.html#crypto_sign_sign_private_key_output_format)), in this case be sure you pass the `algorithm` inside the signing options prefixed by the `sign` key of the plugin registering options).

In this object `{ private, public }` the `public` key is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.

Function based `secret` is supported by the `request.jwtVerify()` and `reply.jwtSign()` methods and is called with `request`, `token`, and `callback` parameters.

#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')
// secret as a string
fastify.register(jwt, { secret: 'supersecret' })
// secret as a function with callback
fastify.register(jwt, {
  secret: function (request, token, callback) {
    // do something
    callback(null, 'supersecret')
  }
})
// secret as a function returning a promise
fastify.register(jwt, {
  secret: function (request, token) {
    return Promise.resolve('supersecret')
  }
})
// secret as an async function
fastify.register(jwt, {
  secret: async function (request, token) {
    return 'supersecret'
  }
})
// secret as an object of RSA keys (without passphrase)
// the files are loaded as strings
fastify.register(jwt, {
  secret: {
    private: readFileSync(`${path.join(__dirname, 'certs')}/private.key`, 'utf8'),
    public: readFileSync(`${path.join(__dirname, 'certs')}/public.key`, 'utf8')
  },
  sign: { algorithm: 'RS256' }
})
// secret as an object of P-256 ECDSA keys (with a passphrase)
// the files are loaded as buffers
fastify.register(jwt, {
  secret: {
    private: {
      key: readFileSync(`${path.join(__dirname, 'certs')}/private.pem`),
      passphrase: 'super secret passphrase'
    },
    public: readFileSync(`${path.join(__dirname, 'certs')}/public.pem`)
  },
  sign: { algorithm: 'ES256' }
})
```
Optionally you can define global default options that will be used by `@fastify/jwt` API if you do not override them.

Additionally, it is also possible to reject tokens selectively (i.e. blacklisting) by providing the option `trusted` with the following signature: `(request, decodedToken) => boolean|Promise<boolean>|SignPayloadType|Promise<SignPayloadType>` where `request` is a `FastifyRequest` and `decodedToken` is the parsed (and verified) token information. Its result should be `false` or `Promise<false>` if the token should be rejected or, otherwise, be `true` or `Promise<true>` if the token should be accepted and, considering that `request.user` will be used after that, the return should be `decodedToken` itself.

#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')
fastify.register(jwt, {
  secret: {
    private: readFileSync(`${path.join(__dirname, 'certs')}/private.pem`, 'utf8')
    public: readFileSync(`${path.join(__dirname, 'certs')}/public.pem`, 'utf8')
  },
  // Global default decoding method options
  decode: { complete: true },
  // Global default signing method options
  sign: {
    algorithm: 'ES256',
    iss: 'api.example.tld'
  },
  // Global default verifying method options
  verify: { allowedIss: 'api.example.tld' }
})

fastify.get('/decode', async (request, reply) => {
  // We clone the global signing options before modifying them
  let altSignOptions = Object.assign({}, fastify.jwt.options.sign)
  altSignOptions.iss = 'another.example.tld'

  // We generate a token using the default sign options
  const token = await reply.jwtSign({ foo: 'bar' })
  // We generate a token using overrided options
  const tokenAlt = await reply.jwtSign({ foo: 'bar' }, altSignOptions)

  // We decode the token using the default options
  const decodedToken = fastify.jwt.decode(token)

  // We decode the token using completely overided the default options
  const decodedTokenAlt = fastify.jwt.decode(tokenAlt, { complete: false })

  return { decodedToken, decodedTokenAlt }
  /**
   * Will return:
   *
   * {
   *   "decodedToken": {
   *     "header": {
   *       "alg": "ES256",
   *       "typ": "JWT"
   *     },
   *     "payload": {
   *       "foo": "bar",
   *       "iat": 1540305336
   *       "iss": "api.example.tld"
   *     },
   *     "signature": "gVf5bzROYB4nPgQC0nbJTWCiJ3Ya51cyuP-N50cidYo"
   *   },
   *   decodedTokenAlt: {
   *     "foo": "bar",
   *     "iat": 1540305337
   *     "iss": "another.example.tld"
   *   },
   * }
   */
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```

### `cookie`

#### Example using cookie

In some situations you may want to store a token in a cookie. This allows you to drastically reduce the attack surface of XSS on your web app with the [`httpOnly`](https://wiki.owasp.org/index.php/HttpOnly) and `secure` flags. Cookies can be susceptible to CSRF. You can mitigate this by either setting the [`sameSite`](https://www.owasp.org/index.php/SameSite) flag to `strict`, or by using a CSRF library such as [`@fastify/csrf`](https://www.npmjs.com/package/@fastify/csrf).

**Note:** This plugin will look for a decorated request with the `cookies` property. [`@fastify/cookie`](https://www.npmjs.com/package/@fastify/cookie) supports this feature, and therefore you should use it when using the cookie feature. The plugin will fallback to looking for the token in the authorization header if either of the following happens (even if the cookie option is enabled):

- The request has both the authorization and cookie header
- Cookie is empty, authorization header is present

If you are signing your cookie, you can set the `signed` boolean to `true` which will make sure the JWT is verified using the unsigned value.

```js
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')

fastify.register(jwt, {
  secret: 'foobar'
  cookie: {
    cookieName: 'token',
    signed: false
  }
})

fastify
  .register(require('@fastify/cookie'))

fastify.get('/cookies', async (request, reply) => {
  const token = await reply.jwtSign({
    name: 'foo',
    role: ['admin', 'spy']
  })

  reply
    .setCookie('token', token, {
      domain: 'your.domain',
      path: '/',
      secure: true, // send cookie over HTTPS only
      httpOnly: true,
      sameSite: true // alternative CSRF protection
    })
    .code(200)
    .send('Cookie sent')
})

fastify.addHook('onRequest', (request) => request.jwtVerify())

fastify.get('/verifycookie', (request, reply) => {
  reply.send({ code: 'OK', message: 'it works!' })
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```


### `onlyCookie`

Setting this options to `true` will decode only the cookie in the request. This is useful for refreshToken implementations where the request typically has two tokens: token and refreshToken. The main authentication token usually has a shorter timeout and the refresh token normally stored in the cookie has a longer timeout. This allows you to check to make sure that the cookie token is still valid, as it could have a different expiring time than the main token. The payloads of the two different tokens could also be different.

```js
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')

fastify.register(jwt, {
  secret: 'foobar',
  cookie: {
    cookieName: 'refreshToken',
  },
  sign: {
    expiresIn: '10m'
  }
})

fastify
  .register(require('@fastify/cookie'))

fastify.get('/cookies', async (request, reply) => {

  const token = await reply.jwtSign({
    name: 'foo'
  })

  const refreshToken = await reply.jwtSign({
    name: 'bar'
  }, {expiresIn: '1d'})

  reply
    .setCookie('refreshToken', refreshToken, {
      domain: 'your.domain',
      path: '/',
      secure: true, // send cookie over HTTPS only
      httpOnly: true,
      sameSite: true // alternative CSRF protection
    })
    .code(200)
    .send({token})
})

fastify.addHook('onRequest', (request) => {
    request.jwtVerify()
    request.jwtVerify({onlyCookie: true})
})

fastify.get('/verifycookie', (request, reply) => {
  reply.send({ code: 'OK', message: 'it works!' })
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```

### `trusted`

#### Example trusted tokens
```js
const fastify = require('fastify')()

fastify.register(require('@fastify/jwt'), {
  secret: 'foobar',
  trusted: validateToken
})

fastify.addHook('onRequest', (request) => request.jwtVerify())

fastify.get('/', (request, reply) => {
  reply.send({ code: 'OK', message: 'it works!' })
})

fastify.listen({ port: 3000 }, (err) => {
  if (err) {
    throw err
  }
})

// ideally this function would do a query against some sort of storage to determine its outcome
async function validateToken(request, decodedToken) {
  const denylist = ['token1', 'token2']

  return !denylist.includes(decodedToken.jti)
}
```

### `formatUser`

#### Example with formatted user
You may customize the `request.user` object setting a custom sync function as parameter:

```js
const fastify = require('fastify')();
fastify.register(require('@fastify/jwt'), {
  formatUser: function (user) {
    return {
      departmentName: user.department_name,
      name: user.name
    }
  },
  secret: 'supersecret'
});

fastify.addHook('onRequest', (request, reply) =>  request.jwtVerify());

fastify.get("/", async (request, reply) => {
  return `Hello, ${request.user.name} from ${request.user.departmentName}.`;
});
```

### `namespace`

To define multiple JWT validators on the same routes, you may use the `namespace` option.
You can combine this with custom names for `jwtVerify` and `jwtSign`.

When you omit the `jwtVerify` and `jwtSign` options, the default function name will be `<namespace>JwtVerify` and `<namespace>JwtSign`.

#### Example with namespace

```js
const fastify = require('fastify')

fastify.register(jwt, {
  secret: 'test',
  namespace: 'security',
  jwtVerify: 'securityVerify',
  jwtSign: 'securitySign'
})

fastify.register(jwt, {
  secret: 'fastify',
  namespace: 'airDrop'
})

// use them like this:
fastify.post('/sign/:namespace', async function (request, reply) {
  switch (request.params.namespace) {
    case 'security':
      return reply.securitySign(request.body)
    default:
      return reply.airDropJwtSign(request.body)
  }
})
```

### `messages`
For your convenience, you can override the default HTTP response messages sent when an unauthorized or bad request error occurs. You can choose the specific messages to override and the rest will fallback to the default messages. The object must be in the format specified in the example below.

#### Example

```js
const fastify = require('fastify')

const myCustomMessages = {
  badRequestErrorMessage: 'Format is Authorization: Bearer [token]',
  noAuthorizationInHeaderMessage: 'Autorization header is missing!',
  authorizationTokenExpiredMessage: 'Authorization token expired',
  // for the below message you can pass a sync function that must return a string as shown or a string
  authorizationTokenInvalid: (err) => {
    return `Authorization token is invalid: ${err.message}`
  }
}

fastify.register(require('@fastify/jwt'), {
  secret: 'supersecret',
  messages: myCustomMessages
})
```

### `decoratorName`
If this plugin is used together with fastify/passport, we might get an error as both plugins use the same name for a decorator. We can change the name of the decorator, or `user` will default

#### Example

```js
const fastify = require('fastify')
fastify.register(require('@fastify/jwt'), {
  secret: 'supersecret',
  decoratorName: 'customName'
})
```

### `decode`

* `complete`: Return an object with the decoded header, payload, signature and input (the token part before the signature), instead of just the content of the payload. Default is `false`.
* `checkTyp`: When validating the decoded header, setting this option forces the check of the typ property against this value. Example: `checkTyp: 'JWT'`. Default is `undefined`.

### `sign`

* `key`: A string or a buffer containing the secret for `HS*` algorithms or the PEM encoded public key for `RS*`, `PS*`, `ES*` and `EdDSA` algorithms. The key can also be a function accepting a Node style callback or a function returning a promise. If provided, it will override the value of [secret](#secret-required) provided in the options.
* `algorithm`: The algorithm to use to sign the token. The default is autodetected from the key, using RS256 for RSA private keys, HS256 for plain secrets and the correspondent ES or EdDSA algorithms for EC or Ed* private keys.
* `mutatePayload`: If set to `true`, the original payload will be modified in place (via `Object.assign`) by the signing function. This is useful if you need a raw reference to the payload after claims have been applied to it but before it has been encoded into a token.
* `expiresIn`: Time span after which the token expires, added as the `exp` claim in the payload. It is expressed in seconds or a string describing a time span (E.g.: `60`, `"2 days"`, `"10h"`, `"7d"`). A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc.), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`). This will override any existing value in the claim.
* `notBefore`: Time span before the token is active, added as the `nbf` claim in the payload. It is expressed in seconds or a string describing a time span (E.g.: `60`, `"2 days"`, `"10h"`, `"7d"`). A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc.), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`). This will override any existing value in the claim.

* ... the rest of the **sign** options can be found [here](https://github.com/nearform/fast-jwt#createsigner).

### `verify`

* `key`: A string or a buffer containing the secret for `HS*` algorithms or the PEM encoded public key for `RS*`, `PS*`, `ES*` and `EdDSA` algorithms. The key can also be a function accepting a Node style callback or a function returning a promise. If provided, it will override the value of [secret](#secret-required) provided in the options.
* `algorithms`: List of strings with the names of the allowed algorithms. By default, all algorithms are accepted.
* `complete`: Return an object with the decoded header, payload, signature and input (the token part before the signature), instead of just the content of the payload. Default is `false`.
* `cache`: A positive number specifying the size of the verified tokens cache (using LRU strategy). Setting this to `true` is equivalent to provide the size 1000. When enabled the  performance is dramatically improved. By default the cache is disabled.
* `cacheTTL`: The maximum time to live of a cache entry (in milliseconds). If the token has a earlier expiration or the verifier has a shorter `maxAge`, the earlier takes precedence. The default is `600000`, which is 10 minutes.
* `maxAge`: The maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span (E.g.: `60`, `"2 days"`, `"10h"`, `"7d"`). A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc.), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`). By default this is not checked.
* ... the rest of the **verify** options can be found [here](https://github.com/nearform/fast-jwt#createverifier).

## API Spec

### fastify.jwt.sign(payload [,options] [,callback])
This method is used to sign the provided `payload`. It returns the token.
The `payload` must be an `Object`. Can be used asynchronously by passing a callback function; synchronously without a callback.
`options` must be an `Object` and can contain [sign](#sign) options.

### fastify.jwt.verify(token, [,options] [,callback])
This method is used to verify provided token. It accepts a `token` (as `Buffer` or a `string`) and returns the payload or the sections of the token. Can be used asynchronously by passing a callback function; synchronously without a callback.
`options` must be an `Object` and can contain [verify](#verify) options.

#### Example
```js
const token = fastify.jwt.sign({ foo: 'bar' })
// synchronously
const decoded = fastify.jwt.verify(token)
// asycnhronously
fastify.jwt.verify(token, (err, decoded) => {
  if (err) fastify.log.error(err)
  fastify.log.info(`Token verified. Foo is ${decoded.foo}`)
})
```

### fastify.jwt.decode(token [,options])
This method is used to decode the provided token. It accepts a token (as a `Buffer` or a `string`) and returns the payload or the sections of the token. 
`options` must be an `Object` and can contain [decode](#decode) options.
Can only be used synchronously.

#### Example
```js
const token = fastify.jwt.sign({ foo: 'bar' })
const decoded = fastify.jwt.decode(token)
fastify.log.info(`Decoded JWT: ${decoded}`)
```

### fastify.jwt.options
For your convenience, the `decode`, `sign`, `verify` and `messages` options you specify during `.register` are made available via `fastify.jwt.options` that will return an object  `{ decode, sign, verify, messages }` containing your options.

#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')
fastify.register(jwt, {
  secret: {
    private: readFileSync(`${path.join(__dirname, 'certs')}/private.key`),
    public: readFileSync(`${path.join(__dirname, 'certs')}/public.key`)
  },
  sign: {
    algorithm: 'RS256',
    aud: 'foo',
    iss: 'example.tld'
  },
  verify: {
    allowedAud: 'foo',
    allowedIss: 'example.tld',
  }
})

fastify.get('/', (request, reply) => {
  const globalOptions = fastify.jwt.options

  // We recommend that you clone the options like this when you need to mutate them
  // modifiedVerifyOptions = { audience: 'foo', issuer: 'example.tld' }
  let modifiedVerifyOptions = Object.assign({}, fastify.jwt.options.verify)
  modifiedVerifyOptions.allowedAud = 'bar'
  modifiedVerifyOptions.allowedSub = 'test'

  return { globalOptions, modifiedVerifyOptions }
  /**
   * Will return :
   * {
   *   globalOptions: {
   *     decode: {},
   *     sign: {
   *       algorithm: 'RS256',
   *       aud: 'foo',
   *       iss: 'example.tld'
   *     },
   *     verify: {
   *       allowedAud: 'foo',
   *       allowedIss: 'example.tld'
   *     }
   *   },
   *   modifiedVerifyOptions: {
   *     allowedAud: 'bar',
   *     allowedIss: 'example.tld',
   *     allowedSub: 'test'
   *   }
   * }
   */
})

fastify.listen({ port: 3000 }, err => {
  if (err) throw err
})
```
### fastify.jwt.cookie
For your convenience, `request.jwtVerify()` will look for the token in the cookies property of the decorated request. You must specify `cookieName`. Refer to the [cookie example](https://github.com/fastify/fastify-jwt#example-using-cookie) to see sample usage and important caveats.

### reply.jwtSign(payload, [options,] callback)

`options` must be an `Object` and can contain `sign` options.

### request.jwtVerify([options,] callback)

`options` must be an `Object` and can contain `verify` and `decode` options.

### request.jwtDecode([options,] callback)

Decode a JWT without verifying

As of 3.2.0, decorated when `options.jwtDecode` is truthy. Will become non-conditionally decorated in 4.0.0. This avoid breaking change that would effect fastify-auth0-verify.

`options` must be an `Object` and can contain `verify` and `decode` options.

### Algorithms supported

The following algorithms are currently supported by [fast-jwt](https://github.com/nearform/fast-jwt) that is internally used by `@fastify/jwt`.

**Name** | **Description**
----------------|----------------------------
none |	Empty algorithm - The token signature section will be empty
HS256 |	HMAC using SHA-256 hash algorithm
HS384 |	HMAC using SHA-384 hash algorithm
HS512 |	HMAC using SHA-512 hash algorithm
ES256 |	ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 |	ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 |	ECDSA using P-521 curve and SHA-512 hash algorithm
RS256 |	RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
RS384 |	RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
RS512 |	RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
PS256 |	RSASSA-PSS using SHA-256 hash algorithm
PS384 |	RSASSA-PSS using SHA-384 hash algorithm
PS512 |	RSASSA-PSS using SHA-512 hash algorithm
EdDSA |	EdDSA tokens using Ed25519 or Ed448 keys, only supported on Node.js 12+

You can find the list [here](https://github.com/nearform/fast-jwt#algorithms-supported).

### Examples

#### Certificates Generation

[Here](./example/UsingCertificates.md) some example on how to generate certificates and use them, with or without passphrase.

#### Signing and verifying (jwtSign, jwtVerify)
```js
const fastify = require('fastify')()
const jwt = require('@fastify/jwt')
const request = require('request')

fastify.register(jwt, {
  secret: function (request, reply, callback) {
    // do something
    callback(null, 'supersecret')
  }
})

fastify.post('/sign', function (request, reply) {
  reply.jwtSign(request.body.payload, function (err, token) {
    return reply.send(err || { 'token': token })
  })
})

fastify.get('/verify', function (request, reply) {
  request.jwtVerify(function (err, decoded) {
    return reply.send(err || decoded)
  })
})

fastify.listen({ port: 3000 }, function (err) {
  if (err) fastify.log.error(err)
  fastify.log.info(`Server live on port: ${fastify.server.address().port}`)

  // sign payload and get JWT
  request({
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: {
      payload: {
        foo: 'bar'
      }
    },
    uri: `http://localhost:${fastify.server.address().port}/sign`,
    json: true
  }, function (err, response, body) {
    if (err) fastify.log.error(err)
    fastify.log.info(`JWT token is ${body.token}`)

    // verify JWT
    request({
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        authorization: 'Bearer ' + body.token
      },
      uri: 'http://localhost:' + fastify.server.address().port + '/verify',
      json: true
    }, function (err, response, body) {
      if (err) fastify.log.error(err)
      fastify.log.info(`JWT verified. Foo is ${body.foo}`)
    })
  })
})
```

#### Verifying with JWKS

The following example integrates the [get-jwks](https://github.com/nearform/get-jwks) package to fetch a JWKS and verify a JWT against a valid public JWK.

##### Example
```js
const Fastify = require('fastify')
const fjwt = require('@fastify/jwt')
const buildGetJwks = require('get-jwks')

const fastify = Fastify()
const getJwks = buildGetJwks()

fastify.register(fjwt, {
  decode: { complete: true },
  secret: (request, token) => {
    const { header: { kid, alg }, payload: { iss } } = token
    return getJwks.getPublicKey({ kid, domain: iss, alg })
  }
})

fastify.addHook('onRequest', async (request, reply) => {
  try {
    await request.jwtVerify()
  } catch (err) {
    reply.send(err)
  }
})

fastify.listen({ port: 3000 })
```

## TypeScript

This plugin has two available exports, the default plugin function `fastifyJwt` and the plugin options object `FastifyJWTOptions`.

Import them like so:

```ts
import fastifyJwt, { FastifyJWTOptions } from '@fastify/jwt'
```


Define custom Payload Type and Attached User Type to request object
> [typescript declaration merging](https://www.typescriptlang.org/docs/handbook/declaration-merging.html)

```ts
// fastify-jwt.d.ts
import "@fastify/jwt"

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: { id: number } // payload type is used for signing and verifying
    user: {
      id: number,
      name: string,
      age: number
      } // user type is return type of `request.user` object
  }
}

// index.ts
fastify.get('/', async (request, reply) => {
  request.user.name // string

  const token = await reply.jwtSign({
    id: '123'
    // ^ Type 'string' is not assignable to type 'number'.
  });
})

```

## Acknowledgements

This project is kindly sponsored by:
- [LetzDoIt](https://www.letzdoitapp.com/)

## License

Licensed under [MIT](./LICENSE).
