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
  fastify.register(jwt, { namespace: 'aaa', secret: 'test', verify: { extractToken: (request) => request.headers.customauthheader } })
  fastify.register(jwt, { namespace: 'bbb', secret: 'sea', verify: { extractToken: (request) => request.headers.customauthheader }, jwtVerify: 'verifyCustom', jwtSign: 'signCustom' })

  fastify.post('/sign/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return reply.jwtSignaaa(request.body)
      default:
        return reply.signCustom(request.body)
    }
  })

  fastify.get('/verify/:namespace', async function (request, reply) {
    switch (request.params.namespace) {
      case 'aaa':
        return request.jwtVerifyaaa()
      default:
        return request.verifyCustom()
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
  t.ok(tokenA)

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
})
