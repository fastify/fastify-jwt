'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('./jwt')

test('fastify-jwt should expose jwt methods', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
    })
})

test('jwt.secretCallback should return the secret given as an option', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      fastify.jwt.secretCallback({}, {}, (err, secret) => {
        t.error(err)
        t.is(secret, 'supersecret')
      })
    })
})

test('sign and verify', t => {
  t.plan(5)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      fastify.jwt.sign({
        body: {
          hello: 'world'
        }
      }, {}, (err, token) => {
        t.error(err)
        t.ok(token)
        fastify.jwt.verify({
          headers: {
            authorization: `Bearer ${token}`
          }
        }, {}, (err, payload) => {
          t.error(err)
          t.equal(payload.hello, 'world')
        })
      })
    })
})

test('should throw if no secret is given as option', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify.register(jwt, err => {
    t.is(err.message, 'missing secret')
  })
})

test('sign should return err if the payload is missing', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      fastify.jwt.sign({}, {}, (err) => {
        t.is(err.message, 'payload is required')
      })
    })
})

test('verify should return err if the token is missing', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      fastify.jwt.verify({}, {}, (err) => {
        t.is(err.message, 'jwt must be provided')
      })
    })
})
