'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const jwt = require('..')

const secret = 'static-signer-test-secret'

test('static secret: reply.jwtSign reuses global signer without per-call options (promise mode)', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/sign', async function (_request, reply) {
    const token = await reply.jwtSign({ user: 'alice' })
    return { token }
  })

  const res = await fastify.inject({ method: 'GET', url: '/sign' })
  t.assert.strictEqual(res.statusCode, 200)

  const body = JSON.parse(res.payload)
  t.assert.ok(body.token)

  const decoded = fastify.jwt.verify(body.token)
  t.assert.strictEqual(decoded.user, 'alice')
})

test('static secret: reply.jwtSign reuses global signer without per-call options (callback mode)', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/sign-cb', function (_request, reply) {
    reply.jwtSign({ user: 'bob' }, function (err, token) {
      if (err) return reply.send(err)
      reply.send({ token })
    })
  })

  const res = await fastify.inject({ method: 'GET', url: '/sign-cb' })
  t.assert.strictEqual(res.statusCode, 200)

  const body = JSON.parse(res.payload)
  t.assert.ok(body.token)

  const decoded = fastify.jwt.verify(body.token)
  t.assert.strictEqual(decoded.user, 'bob')
})

test('static secret: reply.jwtSign with custom per-call options (promise mode)', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/sign-custom', async function (_request, reply) {
    const token = await reply.jwtSign({ user: 'charlie' }, { sign: { jti: 'custom-jti-123' } })
    return { token }
  })

  const res = await fastify.inject({ method: 'GET', url: '/sign-custom' })
  t.assert.strictEqual(res.statusCode, 200)

  const body = JSON.parse(res.payload)
  const decoded = fastify.jwt.verify(body.token)
  t.assert.strictEqual(decoded.user, 'charlie')
  t.assert.strictEqual(decoded.jti, 'custom-jti-123')
})

test('static secret: reply.jwtSign with custom per-call options (callback mode)', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/sign-custom-cb', function (_request, reply) {
    reply.jwtSign({ user: 'david' }, { sign: { jti: 'custom-jti-456' } }, function (err, token) {
      if (err) return reply.send(err)
      reply.send({ token })
    })
  })

  const res = await fastify.inject({ method: 'GET', url: '/sign-custom-cb' })
  t.assert.strictEqual(res.statusCode, 200)

  const body = JSON.parse(res.payload)
  const decoded = fastify.jwt.verify(body.token)
  t.assert.strictEqual(decoded.user, 'david')
  t.assert.strictEqual(decoded.jti, 'custom-jti-456')
})

test('dynamic secret: reply.jwtSign supports both promise and callback modes', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, {
    secret: (_request, _payload, cb) => cb(null, 'dynamic-secret-val')
  })

  fastify.get('/sign-dynamic-promise', async function (_request, reply) {
    const token = await reply.jwtSign({ user: 'eve' })
    return { token }
  })

  fastify.get('/sign-dynamic-cb', function (_request, reply) {
    reply.jwtSign({ user: 'frank' }, function (err, token) {
      if (err) return reply.send(err)
      reply.send({ token })
    })
  })

  const res1 = await fastify.inject({ method: 'GET', url: '/sign-dynamic-promise' })
  t.assert.strictEqual(res1.statusCode, 200)
  const body1 = JSON.parse(res1.payload)
  const decoded1 = fastify.jwt.decode(body1.token)
  t.assert.strictEqual(decoded1.user, 'eve')

  const res2 = await fastify.inject({ method: 'GET', url: '/sign-dynamic-cb' })
  t.assert.strictEqual(res2.statusCode, 200)
  const body2 = JSON.parse(res2.payload)
  const decoded2 = fastify.jwt.decode(body2.token)
  t.assert.strictEqual(decoded2.user, 'frank')
})
