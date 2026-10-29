'use strict'

const { test } = require('node:test')
const crypto = require('node:crypto')
const Fastify = require('fastify')
const jwt = require('..')

const secret = 'test-secret-for-invalid-token-errors'

function encode (value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

// Builds an HS256-signed token without validating its header or payload.
function signHS256 (header, payload) {
  const input = `${encode(header)}.${encode(payload)}`
  const signature = crypto.createHmac('sha256', secret).update(input).digest('base64url')
  return `${input}.${signature}`
}

async function buildServer (t, options) {
  const fastify = Fastify()
  fastify.register(jwt, options)
  fastify.get('/', async function (request) {
    return request.jwtVerify()
  })
  await fastify.ready()
  t.after(() => fastify.close())
  return fastify
}

async function assertInvalidToken (t, fastify, token, message) {
  const response = await fastify.inject({
    method: 'get',
    url: '/',
    headers: { authorization: `Bearer ${token}` }
  })
  t.assert.strictEqual(response.statusCode, 401)
  t.assert.deepStrictEqual(response.json(), {
    statusCode: 401,
    code: 'FST_JWT_AUTHORIZATION_TOKEN_INVALID',
    error: 'Unauthorized',
    message: `Authorization token is invalid: ${message}`
  })
}

test('invalid tokens are rejected with 401', async function (t) {
  const fastify = await buildServer(t, { secret })
  const now = Math.floor(Date.now() / 1000)

  await t.test('token algorithm not allowed for the key', async function (t) {
    const token = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ foo: 'bar' })}.c2lnbmF0dXJl`
    await assertInvalidToken(t, fastify, token, 'The token algorithm is invalid.')
  })

  await t.test('token not active yet', async function (t) {
    const token = signHS256({ alg: 'HS256', typ: 'JWT' }, { foo: 'bar', nbf: now + 3600 })
    await assertInvalidToken(t, fastify, token, `The token will be active at ${new Date((now + 3600) * 1000).toISOString()}.`)
  })

  await t.test('claim with an invalid type', async function (t) {
    const token = signHS256({ alg: 'HS256', typ: 'JWT' }, { foo: 'bar', exp: 'tomorrow' })
    await assertInvalidToken(t, fastify, token, 'The exp claim must be a number.')
  })

  await t.test('payload that is not an object', async function (t) {
    const token = signHS256({ alg: 'HS256', typ: 'JWT' }, ['foo', 'bar'])
    await assertInvalidToken(t, fastify, token, 'The payload must be an object')
  })

  await t.test('unsupported critical header', async function (t) {
    const token = signHS256({ alg: 'HS256', typ: 'JWT', crit: ['foo'], foo: 'bar' }, { foo: 'bar' })
    await assertInvalidToken(t, fastify, token, 'Critical extension "foo" is not supported.')
  })
})

test('token with an unexpected typ is rejected with 401', async function (t) {
  const fastify = await buildServer(t, { secret, verify: { checkTyp: 'JWT' } })
  const token = signHS256({ alg: 'HS256', typ: 'foo' }, { foo: 'bar' })
  await assertInvalidToken(t, fastify, token, 'Invalid typ.')
})

test('token with a malformed ECDSA signature is rejected with 401', async function (t) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  })
  const fastify = await buildServer(t, {
    secret: { private: privateKey, public: publicKey },
    sign: { algorithm: 'ES256' }
  })

  const [header, payload] = fastify.jwt.sign({ foo: 'bar' }).split('.')
  await assertInvalidToken(t, fastify, `${header}.${payload}.c2lnbmF0dXJl`, 'Cannot verify the signature.')
})
