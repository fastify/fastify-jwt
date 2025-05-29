'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const Fastify = require('fastify')
const jwt = require('../jwt')

test('validate option - success case', async (t) => {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'supersecret',
    validate: (payload) => {
      assert.equal(payload.foo, 'bar')
    }
  })

  fastify.get('/protected', {
    handler: async (request, reply) => {
      await request.jwtVerify()
      return { user: request.user }
    }
  })

  await fastify.ready()

  const token = fastify.jwt.sign({ foo: 'bar' })

  const response = await fastify.inject({
    method: 'GET',
    url: '/protected',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.equal(response.statusCode, 200)

  const body = JSON.parse(response.body)
  assert.equal(body.user.foo, 'bar')
  assert.ok(body.user.iat)
})

test('validate option - should throw and block access', async (t) => {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'supersecret',
    validate: (payload) => {
      if (!payload.admin) throw new Error('Unauthorized')
    }
  })

  fastify.get('/admin', {
    handler: async (request, reply) => {
      await request.jwtVerify()
      return { user: request.user }
    }
  })

  await fastify.ready()

  const token = fastify.jwt.sign({ foo: 'bar' })

  const response = await fastify.inject({
    method: 'GET',
    url: '/admin',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.equal(response.statusCode, 500)
  assert.match(response.body, /Unauthorized/)
})

test('validate option - async function', async (t) => {
  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'supersecret',
    validate: async (payload) => {
      if (!payload.verified) throw new Error('Not verified')
    }
  })

  fastify.get('/async-check', {
    handler: async (request, reply) => {
      await request.jwtVerify()
      return { user: request.user }
    }
  })

  await fastify.ready()

  const token = fastify.jwt.sign({ verified: true })

  const response = await fastify.inject({
    method: 'GET',
    url: '/async-check',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  assert.equal(response.statusCode, 200)

  const body = JSON.parse(response.body)
  assert.equal(body.user.verified, true)
  assert.ok(body.user.iat)
})
