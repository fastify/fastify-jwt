'use strict'

const { test } = require('node:test')
const { generateKeyPairSync } = require('node:crypto')
const Fastify = require('fastify')
const { createSigner, TokenError } = require('fast-jwt')
const jwt = require('..')

const secret = 'cache-and-fast-path-secret'

test('reply.jwtSign supports callback mode with dynamic secret functions and caches signers', async function (t) {
  const fastify = Fastify()
  t.after(() => fastify.close())

  let signKeyCalls = 0
  await fastify.register(jwt, {
    secret: {
      private: async function () {
        signKeyCalls += 1
        return secret
      },
      public: secret
    }
  })

  fastify.post('/sign-callback', function (_request, reply) {
    reply.jwtSign({ role: 'callback' }, function (err, token) {
      if (err) return reply.send(err)
      reply.send({ token })
    })
  })

  fastify.post('/sign-promise', async function (_request, reply) {
    return { token: await reply.jwtSign({ role: 'promise' }) }
  })

  fastify.post('/sign-override', async function (_request, reply) {
    return { token: await reply.jwtSign({ role: 'override' }, { iss: 'custom-iss' }) }
  })

  await fastify.ready()

  const cbRes1 = await fastify.inject({ method: 'POST', url: '/sign-callback' })
  t.assert.strictEqual(cbRes1.statusCode, 200)
  t.assert.strictEqual(fastify.jwt.verify(cbRes1.json().token).role, 'callback')

  const cbRes2 = await fastify.inject({ method: 'POST', url: '/sign-callback' })
  t.assert.strictEqual(cbRes2.statusCode, 200)
  t.assert.strictEqual(fastify.jwt.verify(cbRes2.json().token).role, 'callback')

  const promiseRes = await fastify.inject({ method: 'POST', url: '/sign-promise' })
  t.assert.strictEqual(promiseRes.statusCode, 200)
  t.assert.strictEqual(fastify.jwt.verify(promiseRes.json().token).role, 'promise')

  const overrideRes = await fastify.inject({ method: 'POST', url: '/sign-override' })
  t.assert.strictEqual(overrideRes.statusCode, 200)
  const overrideDecoded = fastify.jwt.verify(overrideRes.json().token)
  t.assert.strictEqual(overrideDecoded.role, 'override')
  t.assert.strictEqual(overrideDecoded.iss, 'custom-iss')

  t.assert.strictEqual(signKeyCalls, 4)
})

test('dynamic signer and verifier caches handle Buffer keys, empty keys, async option keys, and FIFO eviction', async function (t) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  })

  const bufferSecret = Buffer.from('buffer-secret-value')
  let signSecret = bufferSecret
  let verifySecret = bufferSecret

  const fastify = Fastify()
  t.after(() => fastify.close())

  await fastify.register(jwt, {
    secret: {
      private: (_request, _payload, cb) => cb(null, signSecret),
      public: (_request, _token, cb) => cb(null, verifySecret)
    }
  })

  fastify.post('/sign', (_request, reply) => reply.jwtSign({ ok: true }))
  fastify.get('/verify', request => request.jwtVerify())

  await fastify.ready()

  // Buffer key caching (> 1 request with Buffer)
  const bufSign1 = await fastify.inject({ method: 'POST', url: '/sign' })
  const bufSign2 = await fastify.inject({ method: 'POST', url: '/sign' })
  t.assert.strictEqual(bufSign1.statusCode, 200)
  t.assert.strictEqual(bufSign2.statusCode, 200)

  const bufVerify1 = await fastify.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: `Bearer ${bufSign1.body}` }
  })
  const bufVerify2 = await fastify.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: `Bearer ${bufSign2.body}` }
  })
  t.assert.strictEqual(bufVerify1.json().ok, true)
  t.assert.strictEqual(bufVerify2.json().ok, true)

  // Empty string / Buffer / null keys bypass cache and fail cleanly
  for (const emptyKey of ['', Buffer.alloc(0), null]) {
    signSecret = emptyKey
    const badSign = await fastify.inject({ method: 'POST', url: '/sign' })
    t.assert.strictEqual(badSign.statusCode, 500)

    verifySecret = emptyKey
    const badVerify = await fastify.inject({
      method: 'GET',
      url: '/verify',
      headers: { authorization: `Bearer ${bufSign1.body}` }
    })
    t.assert.strictEqual(badVerify.statusCode, Buffer.isBuffer(emptyKey) ? 401 : 500)
  }

  // Fill and exceed MAX_KEY_CACHE_SIZE (1000) in both signerCache and validatorCache
  for (let i = 0; i <= 1001; i++) {
    const key = `rotating-secret-${i}`
    signSecret = key
    verifySecret = key

    const signed = await fastify.inject({ method: 'POST', url: '/sign' })
    t.assert.strictEqual(signed.statusCode, 200)

    const verified = await fastify.inject({
      method: 'GET',
      url: '/verify',
      headers: { authorization: `Bearer ${signed.body}` }
    })
    t.assert.strictEqual(verified.statusCode, 200)
    t.assert.strictEqual(verified.json().ok, true)
  }

  // Static secret overridden by async sign.key / verify.key option functions
  const appOptionFn = Fastify()
  t.after(() => appOptionFn.close())

  await appOptionFn.register(jwt, {
    secret: { private: privateKey, public: publicKey },
    sign: { algorithm: 'RS256', key: async () => privateKey },
    verify: { algorithms: ['RS256'], key: async () => publicKey }
  })

  appOptionFn.post('/sign-cb', (_request, reply) => {
    reply.jwtSign({ via: 'option-fn-cb' }, (err, token) => {
      if (err) return reply.send(err)
      reply.send({ token })
    })
  })
  appOptionFn.get('/verify', request => request.jwtVerify())

  await appOptionFn.ready()

  const optSign = await appOptionFn.inject({ method: 'POST', url: '/sign-cb' })
  t.assert.strictEqual(optSign.statusCode, 200)
  const optVerify = await appOptionFn.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: `Bearer ${optSign.json().token}` }
  })
  t.assert.strictEqual(optVerify.statusCode, 200)
  t.assert.strictEqual(optVerify.json().via, 'option-fn-cb')

  // Dynamic secret function paired with global empty string verify.key skips cache
  const emptyKeyOptApp = Fastify()
  t.after(() => emptyKeyOptApp.close())
  await emptyKeyOptApp.register(jwt, {
    secret: async () => secret,
    verify: { algorithms: ['none'], key: '' }
  })
  emptyKeyOptApp.get('/verify', request => request.jwtVerify())
  await emptyKeyOptApp.ready()

  const unsignedTok = createSigner({ algorithm: 'none' })({ sub: 'anon' })
  const emptyKeyRes = await emptyKeyOptApp.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: `Bearer ${unsignedTok}` }
  })
  t.assert.strictEqual(emptyKeyRes.statusCode, 200)
  t.assert.strictEqual(emptyKeyRes.json().sub, 'anon')
})

test('static fast paths handle payload errors, callbacks, lookupToken, verify errors, and trusted hooks', async function (t) {
  const fastify = Fastify()
  t.after(() => fastify.close())

  let trustResult = true
  let trustMode = 'sync'
  let extractedToken = null

  await fastify.register(jwt, {
    secret,
    verify: {
      extractToken: request => extractedToken ?? request.headers.authorization?.replace(/^Bearer\s+/i, '')
    },
    trusted: async function (_request, payload) {
      if (trustMode === 'sync-throw') {
        throw new Error('sync trust boom')
      }
      if (trustMode === 'reject') {
        return Promise.reject(new Error('async trust boom'))
      }
      return trustResult
    }
  })

  // Also test synchronous trusted return in both fast path and slow path
  const syncTrustedApp = Fastify()
  t.after(() => syncTrustedApp.close())
  let syncTrustShouldThrow = false
  let syncTrustValue = true

  await syncTrustedApp.register(jwt, {
    secret,
    trusted: () => {
      if (syncTrustShouldThrow) {
        throw new Error('sync trusted boom')
      }
      return syncTrustValue
    }
  })

  syncTrustedApp.post('/sign-empty-promise', (_req, reply) => reply.jwtSign(null))
  syncTrustedApp.post('/sign-bad-promise', (_req, reply) => reply.jwtSign('not-an-object'))
  syncTrustedApp.post('/sign-empty-cb', (_req, reply) => {
    reply.jwtSign(null, (err, token) => reply.send(err || { token }))
  })
  syncTrustedApp.post('/sign-bad-cb', (_req, reply) => {
    reply.jwtSign('not-an-object', (err, token) => reply.send(err || { token }))
  })
  syncTrustedApp.post('/sign-local-bad', (_req, reply) => reply.jwtSign('not-an-object', { iss: 'foo' }))

  syncTrustedApp.get('/verify-promise', request => request.jwtVerify())
  syncTrustedApp.get('/verify-cb', (request, reply) => {
    request.jwtVerify((err, user) => reply.send(err || user))
  })
  syncTrustedApp.get('/verify-local-options', request => request.jwtVerify({ verify: {} }))

  await syncTrustedApp.ready()

  // reply.jwtSign fast-path error handling (Promise and callback)
  for (const url of ['/sign-empty-promise', '/sign-bad-promise', '/sign-local-bad']) {
    const res = await syncTrustedApp.inject({ method: 'POST', url })
    t.assert.strictEqual(res.statusCode, 500)
  }
  const emptyCb = await syncTrustedApp.inject({ method: 'POST', url: '/sign-empty-cb' })
  t.assert.strictEqual(emptyCb.json().message, 'jwtSign requires a payload')

  const badCb = await syncTrustedApp.inject({ method: 'POST', url: '/sign-bad-cb' })
  t.assert.strictEqual(badCb.json().code, TokenError.codes.invalidType)

  // Public lookupToken API
  const validToken = syncTrustedApp.jwt.sign({ sub: 'alice' })
  t.assert.strictEqual(
    syncTrustedApp.jwt.lookupToken({ headers: { authorization: `Bearer ${validToken}` } }),
    validToken
  )
  t.assert.throws(() => syncTrustedApp.jwt.lookupToken(), /missing request/)

  // Sync trusted fast path & slow path (Promise and callback)
  for (const url of ['/verify-promise', '/verify-cb', '/verify-local-options']) {
    const res = await syncTrustedApp.inject({
      method: 'GET',
      url,
      headers: { authorization: `Bearer ${validToken}` }
    })
    t.assert.strictEqual(res.statusCode, 200)
    t.assert.strictEqual(res.json().sub, 'alice')
  }

  // Sync trusted false in callback mode
  syncTrustValue = false
  const untrustedCb = await syncTrustedApp.inject({
    method: 'GET',
    url: '/verify-cb',
    headers: { authorization: `Bearer ${validToken}` }
  })
  t.assert.strictEqual(untrustedCb.statusCode, 401)
  t.assert.strictEqual(untrustedCb.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_UNTRUSTED')

  // Sync trusted throw in Promise and callback mode
  syncTrustValue = true
  syncTrustShouldThrow = true
  for (const url of ['/verify-promise', '/verify-cb']) {
    const res = await syncTrustedApp.inject({
      method: 'GET',
      url,
      headers: { authorization: `Bearer ${validToken}` }
    })
    t.assert.strictEqual(res.statusCode, 500)
    t.assert.strictEqual(res.json().message, 'sync trusted boom')
  }

  // Callback lookup & verify errors on static fast path
  const missingAuthCb = await syncTrustedApp.inject({ method: 'GET', url: '/verify-cb' })
  t.assert.strictEqual(missingAuthCb.statusCode, 401)

  const malformedCb = await syncTrustedApp.inject({
    method: 'GET',
    url: '/verify-cb',
    headers: { authorization: 'Bearer 1.2.3' }
  })
  t.assert.strictEqual(malformedCb.statusCode, 401)
  t.assert.strictEqual(malformedCb.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')

  // Async trusted callback & non-string extractToken / checkTyp fast path cases
  fastify.get('/verify-cb', (request, reply) => {
    request.jwtVerify((err, user) => reply.send(err || user))
  })
  fastify.get('/verify-promise', request => request.jwtVerify())
  fastify.get('/verify-local', request => request.jwtVerify({ verify: {} }))
  await fastify.ready()

  const asyncTrustedCbPass = await fastify.inject({
    method: 'GET',
    url: '/verify-cb',
    headers: { authorization: `Bearer ${validToken}` }
  })
  t.assert.strictEqual(asyncTrustedCbPass.statusCode, 200)

  const asyncTrustedLocalPass = await fastify.inject({
    method: 'GET',
    url: '/verify-local',
    headers: { authorization: `Bearer ${validToken}` }
  })
  t.assert.strictEqual(asyncTrustedLocalPass.statusCode, 200)

  trustResult = false
  const asyncTrustedCbFail = await fastify.inject({
    method: 'GET',
    url: '/verify-cb',
    headers: { authorization: `Bearer ${validToken}` }
  })
  t.assert.strictEqual(asyncTrustedCbFail.statusCode, 401)

  trustMode = 'reject'
  const asyncTrustedCbReject = await fastify.inject({
    method: 'GET',
    url: '/verify-cb',
    headers: { authorization: `Bearer ${validToken}` }
  })
  t.assert.strictEqual(asyncTrustedCbReject.statusCode, 500)

  // Non-string token from custom extractToken maps invalidType to 401 invalid token
  trustMode = 'sync'
  trustResult = true
  extractedToken = 12345
  const nonStringTokenRes = await fastify.inject({ method: 'GET', url: '/verify-promise' })
  t.assert.strictEqual(nonStringTokenRes.statusCode, 401)
  t.assert.strictEqual(nonStringTokenRes.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_INVALID')
  extractedToken = null

  // verify.checkTyp preserves FAST_JWT_INVALID_TYPE on fast path
  const checkTypApp = Fastify()
  t.after(() => checkTypApp.close())
  await checkTypApp.register(jwt, {
    secret,
    verify: { checkTyp: 'JWT' }
  })
  checkTypApp.get('/verify', request => request.jwtVerify())
  await checkTypApp.ready()

  const badTypToken = createSigner({ key: secret, typ: 'OTHER' })({ sub: 'bob' })
  const badTypRes = await checkTypApp.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: `Bearer ${badTypToken}` }
  })
  t.assert.strictEqual(badTypRes.statusCode, 500)
  t.assert.strictEqual(badTypRes.json().code, TokenError.codes.invalidType)

  // Static fast-path malformed token without decode.checkTyp uses custom string message cleanly
  const customMsgApp = Fastify()
  t.after(() => customMsgApp.close())
  await customMsgApp.register(jwt, {
    secret,
    messages: { authorizationTokenInvalid: 'invalid token' }
  })
  customMsgApp.get('/verify', request => request.jwtVerify())
  await customMsgApp.ready()

  const malformedCustomRes = await customMsgApp.inject({
    method: 'GET',
    url: '/verify',
    headers: { authorization: 'Bearer 1.2.3' }
  })
  t.assert.strictEqual(malformedCustomRes.statusCode, 401)
  t.assert.strictEqual(malformedCustomRes.json().message, 'invalid token')
})
