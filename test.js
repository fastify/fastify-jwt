'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('./jwt')

test('fastify-jwt should expose jwt methods', t => {
  t.plan(5)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.secret)
    })
})

test('jwt.secret should be the same as the one given as option', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      t.is(fastify.jwt.secret, 'supersecret')
    })
})

test('sync sign and verify', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      const token = fastify.jwt.sign({ hello: 'world' })
      t.ok(token)
      t.equal(fastify.jwt.verify(token).hello, 'world')
    })
})

test('async sign and verify', t => {
  t.plan(5)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      fastify.jwt.sign({ hello: 'world' }, (err, token) => {
        t.error(err)
        t.ok(token)
        fastify.jwt.verify(token, (err, payload) => {
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

test('sign should throw if the payload is missing', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      try {
        fastify.jwt.sign()
        t.fail()
      } catch (err) {
        t.is(err.message, 'missing payload')
      }
    })
})

test('verify should throw if the token is missing', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)
    .after(() => {
      try {
        fastify.jwt.verify()
        t.fail()
      } catch (err) {
        t.is(err.message, 'missing token')
      }
    })
})
