'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('../jwt')

test('Async key provider should be resolved internally', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: {
      private: 'supersecret',
      public: async () => Promise.resolve('supersecret')
    },
    verify: {
      extractToken: (request) => request.headers.jwt,
      key: () => Promise.resolve('supersecret')
    }
  })
  fastify.get('/', async function (request, reply) {
    const token = await reply.jwtSign({ user: 'test' })
    request.headers.jwt = token
    await request.jwtVerify()
    return reply.send(request.user)
  })
  const response = await fastify.inject({
    method: 'get',
    url: '/',
    headers: {
      jwt: 'supersecret'
    }
  })
  t.ok(response)
  t.comment("Should be 'undefined'")
  t.match(response.json(), { user: 'test' })
})

test('Async key provider errors should be resolved internally', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: {
      public: async () => Promise.resolve('key used per request, false not allowed')
    },
    verify: {
      extractToken: (request) => request.headers.jwt,
      key: () => Promise.resolve('key not used')
    }
  })
  fastify.get('/', async function (request, reply) {
    request.headers.jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    // call to local verifier without cache
    await request.jwtVerify()
    return reply.send(typeof request.user.then)
  })
  const response = await fastify.inject({
    method: 'get',
    url: '/'
  })

  t.equal(response.statusCode, 401)
})

test('Async key provider should be resolved internally with cache', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: {
      public: async () => false
    },
    verify: {
      extractToken: (request) => request.headers.jwt,
      key: () => Promise.resolve('this secret reused from cache')
    }
  })
  fastify.get('/', async function (request, reply) {
    request.headers.jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hQOxra1Zo9z61vCqe6_86kVfLqKI0WxDnkiJ_upW0sM'
    await new Promise((resolve, reject) => request.jwtVerify((err, payload) => {
      if (err) {
        reject(err)
        return
      }
      resolve(payload)
    }))
    await new Promise((resolve, reject) => request.jwtVerify((err, payload) => {
      if (err) {
        reject(err)
        return
      }
      resolve(payload)
    }))
    return reply.send(request.user)
  })
  const response = await fastify.inject({
    method: 'get',
    url: '/'
  })
  t.equal(response.statusCode, 200)
  t.match(response.json(), { name: 'John Doe' })
})

test('Async key provider errors should be resolved internally with cache', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: {
      public: async () => false
    },
    verify: {
      extractToken: (request) => request.headers.jwt,
      key: () => Promise.resolve('this secret reused from cache')
    }
  })
  fastify.get('/', async function (request, reply) {
    request.headers.jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    // call to plugin root level verifier
    await new Promise((resolve, reject) => request.jwtVerify((err, payload) => {
      if (err) {
        reject(err)
        return
      }
      resolve(payload)
    }))
    return reply.send(typeof request.user.then)
  })
  const response = await fastify.inject({
    method: 'get',
    url: '/'
  })

  t.equal(response.statusCode, 401)
})
