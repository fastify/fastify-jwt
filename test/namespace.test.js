'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const jwt = require('../jwt')

test('Unable to add the namespace twice', async function (t) {
  t.plan(1)
  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', namespace: 'security', jwtVerify: 'securityVerify', jwtSign: 'securitySign' })

  await t.assert.rejects(() => fastify.register(jwt, { secret: 'hello', namespace: 'security', jwtVerify: 'secureVerify', jwtSign: 'secureSign' })
    .ready(), new Error('JWT namespace already used "security"'))
})

test('multiple namespace', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, { namespace: 'aaa', secret: 'test', verify: { extractToken: (request) => request.headers.customauthheader } })
  fastify.register(jwt, { namespace: 'bbb', secret: 'sea', verify: { extractToken: (request) => request.headers.customauthheader }, jwtVerify: 'verifyCustom', jwtSign: 'signCustom', jwtDecode: 'decodeCustom' })

  fastify.post('/sign/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return reply.aaaJwtSign(request.body)
      case 'bbb':
        return reply.signCustom(request.body)
      default:
        reply.code(501).send({ message: `Namespace ${request.params.namespace} is not implemented correctly` })
    }
  })

  fastify.get('/verify/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return request.aaaJwtVerify()
      case 'bbb':
        return request.verifyCustom()
      default:
        reply.code(501).send({ message: `Namespace ${request.params.namespace} is not implemented correctly` })
    }
  })

  fastify.get('/decode/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return request.aaaJwtDecode()
      case 'bbb':
        return request.decodeCustom()
      default:
        reply.code(501).send({ message: `Namespace ${request.params.namespace} is not implemented correctly` })
    }
  })

  await fastify.ready()

  let signResponse
  let verifyResponse

  signResponse = await fastify.inject({
    method: 'post',
    url: '/sign/aaa',
    payload: { foo: 'bar' }
  })
  const tokenA = signResponse.payload
  t.assert.ok(tokenA)

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/aaa',
    headers: {
      customauthheader: tokenA
    }
  })
  t.assert.deepStrictEqual(verifyResponse.statusCode, 200)
  t.assert.deepStrictEqual(verifyResponse.json().foo, 'bar')

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/bbb',
    headers: {
      customauthheader: tokenA
    }
  })
  t.assert.deepStrictEqual(verifyResponse.statusCode, 401)

  signResponse = await fastify.inject({
    method: 'post',
    url: '/sign/bbb',
    payload: { foo: 'sky' }
  })
  const tokenB = signResponse.payload
  t.assert.ok(tokenB)

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/bbb',
    headers: {
      customauthheader: tokenB
    }
  })
  t.assert.deepStrictEqual(verifyResponse.statusCode, 200)
  t.assert.deepStrictEqual(verifyResponse.json().foo, 'sky')

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/aaa',
    headers: {
      customauthheader: tokenB
    }
  })
  t.assert.deepStrictEqual(verifyResponse.statusCode, 401)

  const decodeResponseAAA = await fastify.inject({
    method: 'get',
    url: '/decode/aaa',
    headers: {
      customauthheader: tokenA
    }
  })
  t.assert.deepStrictEqual(decodeResponseAAA.statusCode, 200)
  t.assert.deepStrictEqual(decodeResponseAAA.json().foo, 'bar')

  const verifyResponseBBB = await fastify.inject({
    method: 'get',
    url: '/decode/bbb',
    headers: {
      customauthheader: tokenB
    }
  })
  t.assert.deepStrictEqual(verifyResponseBBB.statusCode, 200)
  t.assert.deepStrictEqual(verifyResponseBBB.json().foo, 'sky')
})
