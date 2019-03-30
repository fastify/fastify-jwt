# fastify-jwt

[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/)  [![Build Status](https://travis-ci.org/fastify/fastify-jwt.svg?branch=master)](https://travis-ci.org/fastify/fastify-jwt) [![Greenkeeper badge](https://badges.greenkeeper.io/fastify/fastify-jwt.svg)](https://greenkeeper.io/)

JWT utils for Fastify, internally uses [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Install
```
npm i fastify-jwt --save
```

## Usage
Register as a plugin. This will decorate your `fastify` instance with the standard [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) methods `decode`, `sign`, and `verify`; refer to their documentation to find how to use the utilities. It will also register `request.jwtVerify` and `reply.jwtSign`. You must pass a `secret` when registering the plugin.

```js
const fastify = require('fastify')
fastify.register(require('fastify-jwt'), {
  secret: 'supersecret'
})

fastify.post('/signup', (req, reply) => {
  // some code
  const token = fastify.jwt.sign({ payload })
  reply.send({ token })
})

fastify.listen(3000, err => {
  if (err) throw err
})
```

For verifying & accessing the decoded token inside your services, you can use a global `onRequest` hook to define the verification process like so:

```js
const fastify = require('fastify')
fastify.register(require('fastify-jwt'), {
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

Aftewards, just use `request.user` in order to retrieve the user information:

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
  fastify.register(require("fastify-jwt"), {
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

Then use the `preValidation` of a route to protect it & access the user information inside:

```js
module.exports = async function(fastify, opts) {
  fastify.get(
    "/",
    {
      preValidation: [fastify.authenticate]
    },
    async function(request, reply) {
      return request.user
    }
  )
}
```

Make sure that you also check [fastify-auth](https://github.com/fastify/fastify-auth) plugin for composing more complex strategies.

## API Spec

### fastify-jwt
`fastify-jwt` is a fastify plugin. You must pass a `secret` to the `options` parameter. The `secret` can be a primitive type String, a function that returns a String or an object `{ private, public }`.

In this object `{ private, public }` the `private` key is a string, buffer or object containing either the secret for HMAC algorithms or the PEM encoded private key for RSA and ECDSA. In case of a private key with passphrase an object `{ private: { key, passphrase }, public }` can be used (based on [crypto documentation](https://nodejs.org/api/crypto.html#crypto_sign_sign_private_key_output_format)), in this case be sure you pass the `algorithm` inside the signing options prefixed by the `sign` key of the plugin registering options).

In this object `{ private, public }` the `public` key is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.

Function based `secret` is supported by the `request.jwtVerify()` and `reply.jwtSign()` methods and is called with `request`, `reply`, and `callback` parameters.
#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')
// secret as a string
fastify.register(jwt, { secret: 'supersecret' })
// secret as a function
fastify.register(jwt, {
  secret: function (request, reply, callback) {
    // do something
    callback(null, 'supersecret')
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
Optionaly you can define global default options that will be used by `fastify-jwt` API if you don't override them.

#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')
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
    issuer: 'api.example.tld'
  },
  // Global default verifying method options
  verify: { issuer: 'api.example.tld' }
})

fastify.get('/decode', async (request, reply) => {
  // We clone the global signing options before modifying them
  let altSignOptions = Object.assign({}, fastify.jwt.options.sign)
  altSignOptions.issuer = 'another.example.tld'

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

fastify.listen(3000, err => {
  if (err) throw err
})
```

#### Example using cookie

Storing JWT in Cookie mean that your app maybe vunerable to XSS attack and must be protected with CSRF token,
consider that as a best practice. but storing JWT on cookies makes your REST API arent Stateless anymore, choose what fit for you.
You can use [crsf](https://www.npmjs.com/package/csrf) or other library that may suit your need.

```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')
const Redis = require('ioredis')

const redis = new Redis()
const abcache = require('abstract-cache')({
  useAwait: false,
  driver: {
    name: 'abstract-cache-redis', // Must be installed via `npm install`
    options: { client: redis }
  }
})

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

fastify
  .register(require('fastify-redis'), { client: redis })
  .register(require('fastify-cookie'))
  .register(require('fastify-caching'), { cache: abcache })
  .register(require('fastify-server-session'), {
    secretKey: 'your secret key',
    sessionMaxAge: 900000 // 15 minutes in milliseconds
  })

fastify.get('/cookies', async (request, reply) => {
  const token = await reply.jwtSign({
    name: 'foo',
    role: ['admin', 'spy']
    // you may registering your csrf here
  })

  reply
    .setCookie('token', token, {
      domain: '.domain',
      path: '/'
    })
    .code(200)
    .send('Cookies are send!')
})

fastify.get('/verifyCookies', async (request, reply) => {
  try {
    const verified = await fastify.jwt.verify(request.cookies.token)
    reply.code(200).send(verified)
  } catch (err) {
    reply.code(401).send(err)
  }
})

fastify.listen(3000, err => {
  if (err) throw err
})
```

### fastify.jwt.sign(payload [,options] [,callback])
The `sign` method is an implementation of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback) `.sign()`. Can be used asynchronously by passing a callback function; synchronously without a callback.

### fastify.jwt.verify(token, [,options] [,callback])
The `verify` method is an implementation of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) `.verify()`. Can be used asynchronously by passing a callback function; synchronously without a callback.
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
The `decode` method is an implementation of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options) `.decode()`. Can only be used synchronously.
#### Example
```js
const token = fastify.jwt.sign({ foo: 'bar' })
const decoded = fastify.jwt.decode(token)
fastify.log.info(`Decoded JWT: ${decoded}`)
```

### fastify.jwt.options
For your convenience, the `decode`, `sign` and `verify` options you specify during `.register` are made available via `fastify.jwt.options` that will return an object  `{ decode, sign, verify }` containing your options.

#### Example
```js
const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')
fastify.register(jwt, {
  secret: {
    private: readFileSync(`${path.join(__dirname, 'certs')}/private.key`),
    public: readFileSync(`${path.join(__dirname, 'certs')}/public.key`)
  },
  sign: {
    algorithm: 'RS256',
    audience: 'foo',
    issuer: 'example.tld'
  },
  verify: {
    audience: 'foo',
    issuer: 'example.tld',
  }
})

fastify.get('/', (request, reply) => {
  const globalOptions = fastify.jwt.options

  // We recommend that you clone the options like this when you need to mutate them
  // modifiedVerifyOptions = { audience: 'foo', issuer: 'example.tld' }
  let modifiedVerifyOptions = Object.assign({}, fastify.jwt.options.verify)
  modifiedVerifyOptions.audience = 'bar'
  modifiedVerifyOptions.subject = 'test'

  return { globalOptions, modifiedVerifyOptions }
  /**
   * Will return :
   * {
   *   globalOptions: {
   *     decode: {},
   *     sign: {
   *       algorithm: 'RS256',
   *       audience: 'foo',
   *       issuer: 'example.tld'
   *     },
   *     verify: {
   *       audience: 'foo',
   *       issuer: 'example.tld'
   *     }
   *   },
   *   modifiedVerifyOptions: {
   *     audience: 'bar',
   *     issuer: 'example.tld',
   *     subject: 'test'
   *   }
   * }
   */
})

fastify.listen(3000, err => {
  if (err) throw err
})
```

#### decode options
* `json`: force JSON.parse on the payload even if the header doesn't contain `"typ":"JWT"`.
* `complete`: return an object with the decoded payload and header.

#### sign options
* `algorithm` (default: `HS256`)
* `expiresIn`: expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms). Eg: `60`, `"2 days"`, `"10h"`, `"7d"`. A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`).
* `notBefore`: expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms). Eg: `60`, `"2 days"`, `"10h"`, `"7d"`. A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`).
* `audience`
* `issuer`
* `jwtid`
* `subject`
* `noTimestamp`
* `header`
* `keyid`
* `mutatePayload`: if true, the sign function will modify the payload object directly. This is useful if you need a raw reference to the payload after claims have been applied to it but before it has been encoded into a token.

#### verify options

* `algorithms`: List of strings with the names of the allowed algorithms. For instance, `["HS256", "HS384"]`.
* `audience`: if you want to check audience (`aud`), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions. Eg: `"urn:foo"`, `/urn:f[o]{2}/`, `[/urn:f[o]{2}/, "urn:bar"]`
* `issuer` (optional): string or array of strings of valid values for the `iss` field.
* `ignoreExpiration`: if `true` do not validate the expiration of the token.
* `ignoreNotBefore`...
* `subject`: if you want to check subject (`sub`), provide a value here
* `clockTolerance`: number of seconds to tolerate when checking the `nbf` and `exp` claims, to deal with small clock differences among different servers
* `maxAge`: the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms). Eg: `1000`, `"2 days"`, `"10h"`, `"7d"`. A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`).
* `clockTimestamp`: the time in seconds that should be used as the current time for all necessary comparisons.

### fastify.jwt.secret
For your convenience, the `secret` you specify during `.register` is made available via `fastify.jwt.secret`. `request.jwtVerify()` and `reply.jwtSign()` will wrap non-function secrets in a callback function. `request.jwtVerify()` and `reply.jwtSign()` use an asynchronous waterfall method to retrieve your secret. It's recommended that your use these methods if your `secret` method is asynchronous.

### reply.jwtSign(payload, [options,] callback)
### request.jwtVerify([options,] callback)
These methods are very similar to their standard jsonwebtoken counterparts.
#### Example
```js
const fastify = require('fastify')()
const jwt = require('fastify-jwt')
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

fastify.listen(3000, function (err) {
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

### Algorithms supported

The following algorithms are currently supported by [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#algorithms-supported) that is internally used by `fastify-jwt`.

algorithm(s) Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included

## Acknowledgements

This project is kindly sponsored by:
- [LetzDoIt](http://www.letzdoitapp.com/)

## License

Licensed under [MIT](./LICENSE).
