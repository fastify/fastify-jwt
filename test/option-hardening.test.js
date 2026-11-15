'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const { createSigner, TokenError } = require('fast-jwt')
const jwt = require('..')

const secret = 'option-hardening-secret'

function unsignedToken (alg, payload) {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url')
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${encodedPayload}.`
}

test('undefined per-call options preserve global defaults', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, {
    secret,
    decode: { checkTyp: 'JWT' },
    sign: { iss: 'trusted' },
    verify: { allowedIss: 'trusted' }
  })

  fastify.get('/sign-flat', function (_request, reply) {
    return reply.jwtSign({ value: true }, { iss: undefined, jti: 'flat' })
  })
  fastify.get('/sign-nested', function (_request, reply) {
    return reply.jwtSign({ value: true }, { sign: { iss: undefined, jti: 'nested' } })
  })
  fastify.get('/verify-flat', function (request) {
    return request.jwtVerify({ allowedIss: undefined })
  })
  fastify.get('/verify-nested', function (request) {
    return request.jwtVerify({ verify: { allowedIss: undefined } })
  })
  fastify.get('/decode-nested', function (request) {
    return request.jwtDecode({ decode: { checkTyp: undefined } })
  })

  await fastify.ready()
  t.after(() => fastify.close())

  const directToken = fastify.jwt.sign(
    { value: true },
    { iss: undefined, jti: 'direct' }
  )
  const directPayload = fastify.jwt.decode(directToken)
  t.assert.strictEqual(directPayload.iss, 'trusted')
  t.assert.strictEqual(directPayload.jti, 'direct')

  const untrustedIssuerToken = createSigner({ key: secret, iss: 'untrusted' })({ value: true })
  t.assert.throws(
    () => fastify.jwt.verify(untrustedIssuerToken, { allowedIss: undefined }),
    error => error.code === TokenError.codes.invalidClaimValue
  )

  for (const [url, jti] of [
    ['/sign-flat', 'flat'],
    ['/sign-nested', 'nested']
  ]) {
    const response = await fastify.inject(url)
    t.assert.strictEqual(response.statusCode, 200)
    const payload = fastify.jwt.decode(response.body)
    t.assert.strictEqual(payload.iss, 'trusted')
    t.assert.strictEqual(payload.jti, jti)
  }

  const authorization = { authorization: `Bearer ${untrustedIssuerToken}` }
  for (const url of ['/verify-flat', '/verify-nested']) {
    const response = await fastify.inject({ url, headers: authorization })
    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(response.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
  }

  const wrongTypeToken = createSigner({ key: secret, typ: 'NOT-JWT' })({ value: true })
  const decodeResponse = await fastify.inject({
    url: '/decode-nested',
    headers: { authorization: `Bearer ${wrongTypeToken}` }
  })
  t.assert.strictEqual(decodeResponse.statusCode, 401)
  t.assert.strictEqual(decodeResponse.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
})

test('route methods reject mixed flat and nested options', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/sign-mixed', function (_request, reply) {
    return reply.jwtSign(
      { value: true },
      { sign: { jti: 'mixed' }, expiresIn: 60 }
    )
  })
  fastify.get('/verify-mixed', function (request) {
    return request.jwtVerify({ decode: {}, maxAge: 1 })
  })
  fastify.get('/sign-extended', function (_request, reply) {
    return reply.jwtSign(
      { value: true },
      { sign: { expiresIn: 60 }, verify: {}, decode: {} }
    )
  })

  await fastify.ready()
  t.after(() => fastify.close())

  const signResponse = await fastify.inject('/sign-mixed')
  t.assert.strictEqual(signResponse.statusCode, 500)
  t.assert.strictEqual(signResponse.json().code, TokenError.codes.invalidOption)
  t.assert.strictEqual(
    signResponse.json().message,
    'The options must use either the flat or nested format, not both.'
  )

  const oldToken = createSigner({ key: secret })({
    value: true,
    iat: Math.floor(Date.now() / 1000) - 10
  })
  const verifyResponse = await fastify.inject({
    url: '/verify-mixed',
    headers: { authorization: `Bearer ${oldToken}` }
  })
  t.assert.strictEqual(verifyResponse.statusCode, 500)
  t.assert.strictEqual(verifyResponse.json().code, TokenError.codes.invalidOption)
  t.assert.strictEqual(
    verifyResponse.json().message,
    'The options must use either the flat or nested format, not both.'
  )

  const extendedResponse = await fastify.inject('/sign-extended')
  t.assert.strictEqual(extendedResponse.statusCode, 200)
  const extendedPayload = fastify.jwt.decode(extendedResponse.body)
  t.assert.strictEqual(extendedPayload.exp - extendedPayload.iat, 60)
})

test('fast-jwt rejects empty per-call verification keys', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, {
    secret,
    verify: { algorithms: ['HS256'] }
  })

  fastify.get('/verify-empty-key', function (request) {
    return request.jwtVerify({ verify: { key: '' } })
  })

  await fastify.ready()
  t.after(() => fastify.close())

  const token = unsignedToken('HS256', { sub: 'attacker', admin: true })

  for (const key of ['', null]) {
    t.assert.throws(
      () => fastify.jwt.verify(token, { key }),
      error => error.code === TokenError.codes.invalidKey
    )
  }

  const response = await fastify.inject({
    url: '/verify-empty-key',
    headers: { authorization: `Bearer ${token}` }
  })
  t.assert.strictEqual(response.statusCode, 401)
  t.assert.strictEqual(response.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
})

test('fast-jwt cache rejects tokens after exp when iat is absent', async function (t) {
  const originalNow = Date.now
  const initialNow = 1_700_000_000_000
  const exp = Math.floor(initialNow / 1000) + 1
  const token = createSigner({
    key: secret,
    algorithm: 'HS256',
    noTimestamp: true
  })({ value: true, exp })

  const fastify = Fastify()
  await fastify.register(jwt, {
    secret,
    verify: {
      algorithms: ['HS256'],
      cache: true,
      cacheTTL: 60_000
    }
  }).ready()

  try {
    Date.now = () => initialNow
    t.assert.strictEqual(fastify.jwt.verify(token).value, true)

    Date.now = () => exp * 1000 + 1
    t.assert.throws(
      () => fastify.jwt.verify(token),
      error => error.code === TokenError.codes.expired
    )
  } finally {
    Date.now = originalNow
    await fastify.close()
  }
})
