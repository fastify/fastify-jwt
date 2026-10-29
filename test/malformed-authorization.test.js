'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const jwt = require('..')

test('empty Bearer token returns a bad request', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test' })
  fastify.get('/', function (request) {
    return request.jwtVerify()
  })

  await fastify.ready()

  const response = await fastify.inject({
    method: 'GET',
    url: '/',
    headers: {
      authorization: 'Bearer '
    }
  })

  t.assert.strictEqual(response.statusCode, 400)
  t.assert.strictEqual(response.json().code, 'FST_JWT_BAD_REQUEST')
  t.assert.strictEqual(response.json().message, 'Format is Authorization: Bearer [token]')

  await fastify.close()
})
