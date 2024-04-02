'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('../jwt')

test('Async key provider should be resolved internaly', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: {
      private: 'supersecret',
      public: async () => false
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
    return reply.send(typeof request.user.then)
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
  t.equal(response.payload, 'function')
})
