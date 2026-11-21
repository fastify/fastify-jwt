'use strict'

const { test } = require('node:test')
const { createHmac, createPublicKey } = require('node:crypto')
const Fastify = require('fastify')
const jwt = require('..')

const helper = require('./helper')

const { publicKey } = helper.generateKeyPair()
const zeroWidthSpace = '\u200b'

function forgeHS256Token (secret, payload) {
  const encode = part => Buffer.from(JSON.stringify(part)).toString('base64url')
  const data = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`
  const signature = createHmac('sha256', secret).update(data).digest('base64url')
  return `${data}.${signature}`
}

async function verifyForgedToken (key) {
  const fastify = Fastify()
  fastify.register(jwt, { secret: async function () { return key } })

  fastify.get('/protected', async function (request) {
    return request.jwtVerify()
  })

  await fastify.ready()

  const response = await fastify.inject({
    method: 'GET',
    url: '/protected',
    headers: { authorization: `Bearer ${forgeHS256Token(key, { sub: 'attacker' })}` }
  })

  await fastify.close()
  return response
}

test('public key material is not usable as an HMAC secret', async function (t) {
  t.plan(3)

  await t.test('serialized asymmetric JWK', async function (t) {
    t.plan(2)

    const jwk = JSON.stringify(createPublicKey(publicKey).export({ format: 'jwk' }))
    const response = await verifyForgedToken(jwk)

    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(JSON.parse(response.payload).code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
  })

  await t.test('serialized asymmetric JWKS', async function (t) {
    t.plan(2)

    const jwks = JSON.stringify({ keys: [createPublicKey(publicKey).export({ format: 'jwk' })] })
    const response = await verifyForgedToken(jwks)

    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(JSON.parse(response.payload).code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
  })

  await t.test('PEM hidden behind a zero width character', async function (t) {
    t.plan(1)

    const response = await verifyForgedToken(`${zeroWidthSpace}${publicKey}`)

    t.assert.notStrictEqual(response.statusCode, 200, 'the forged HS256 token must not authenticate the request')
  })
})

test('a symmetric JWK is still usable as an HMAC secret', async function (t) {
  t.plan(1)

  const fastify = Fastify()
  fastify.register(jwt, { secret: JSON.stringify({ kty: 'oct', k: 'c3VwZXJzZWNyZXQ' }) })
  await fastify.ready()

  const token = fastify.jwt.sign({ foo: 'bar' })
  t.assert.strictEqual(fastify.jwt.verify(token).foo, 'bar')

  await fastify.close()
})
