'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('../jwt')

test('Unable to add the namespace twice', function (t) {
  t.plan(1)
  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', namespace: 'security', jwtVerify: 'securityVerify', jwtSign: 'securitySign' })
  fastify.register(jwt, { secret: 'hello', namespace: 'security', jwtVerify: 'secureVerify', jwtSign: 'secureSign' })
    .ready(function (err) {
      t.equal(err.message, 'JWT namespace already used "security"')
    })
})

test('multiple namespace', async function (t) {
  const fastify = Fastify()
  fastify.register(jwt, { namespace: 'aaa', secret: 'test', verify: { extractToken: (request) => request.headers.customauthheader }, jwtDecode: true })
  fastify.register(jwt, { namespace: 'bbb', secret: 'sea', verify: { extractToken: (request) => request.headers.customauthheader }, jwtVerify: 'verifyCustom', jwtSign: 'signCustom', jwtDecode: 'decodeCustom' })
  fastify.register(jwt, { namespace: 'ccc', secret: 'tset', verify: { extractToken: (request) => request.headers.customauthheader } })

  fastify.post('/sign/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return reply.aaaJwtSign(request.body)
      case 'ccc':
        return reply.cccJwtSign(request.body)
      default:
        return reply.signCustom(request.body)
    }
  })

  fastify.get('/verify/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return request.aaaJwtVerify()
      default:
        return request.verifyCustom()
    }
  })

  fastify.get('/decode/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return request.jwtDecode()
      case 'bbb':
        return request.decodeCustom()
      case 'ccc':
        return request.cccJwtDecode()
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
  t.ok(tokenA)

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/aaa',
    headers: {
      customauthheader: tokenA
    }
  })
  t.equal(verifyResponse.statusCode, 200)
  t.match(verifyResponse.json(), { foo: 'bar' })

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/bbb',
    headers: {
      customauthheader: tokenA
    }
  })
  t.equal(verifyResponse.statusCode, 401)

  signResponse = await fastify.inject({
    method: 'post',
    url: '/sign/bbb',
    payload: { foo: 'sky' }
  })
  const tokenB = signResponse.payload
  t.ok(tokenB)

  signResponse = await fastify.inject({
    method: 'post',
    url: '/sign/ccc',
    payload: { foo: 'tset' }
  })
  const tokenC = signResponse.payload
  t.ok(tokenC)

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/bbb',
    headers: {
      customauthheader: tokenB
    }
  })
  t.equal(verifyResponse.statusCode, 200)
  t.match(verifyResponse.json(), { foo: 'sky' })

  verifyResponse = await fastify.inject({
    method: 'get',
    url: '/verify/aaa',
    headers: {
      customauthheader: tokenB
    }
  })
  t.equal(verifyResponse.statusCode, 401)

  const decodeResponseAAA = await fastify.inject({
    method: 'get',
    url: '/decode/aaa',
    headers: {
      customauthheader: tokenA
    }
  })
  t.equal(decodeResponseAAA.statusCode, 200)
  t.match(decodeResponseAAA.json(), { foo: 'bar' })

  const verifyResponseBBB = await fastify.inject({
    method: 'get',
    url: '/decode/bbb',
    headers: {
      customauthheader: tokenB
    }
  })
  t.equal(verifyResponseBBB.statusCode, 200)
  t.match(verifyResponseBBB.json(), { foo: 'sky' })

  const verifyResponseCCC = await fastify.inject({
    method: 'get',
    url: '/decode/ccc',
    headers: {
      customauthheader: tokenC
    }
  })
  t.equal(verifyResponseCCC.statusCode, 200)
  t.match(verifyResponseCCC.json(), { foo: 'tset' })
})
