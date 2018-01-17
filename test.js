'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('./jwt')

test('fastify-jwt should expose jwt methods', t => {
  t.plan(4)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.secretCallback)
    })
})

test('jwt.secretCallback should return the secret given as an option', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
      fastify.jwt.secretCallback({}, {}, (err, secret) => {
        t.error(err)
        t.is(secret, 'supersecret')
      })
    })
})

test('secretCallback should not be wrapped if secret option is a function', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: (req, res, cb) => {
      cb(null, 'superSecretFunction')
    } })
    .ready(() => {
      fastify.jwt.secretCallback({}, {}, (err, secret) => {
        t.error(err)
        t.is(secret, 'superSecretFunction')
      })
    })
})

test('sign and verify', t => {
  t.plan(4)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
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
  fastify
    .register(jwt, {})
    .ready(err => {
      t.is(err.message, 'missing secret')
    })
})

test('decode', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh' })
    .ready(() => {
      fastify.jwt.sign({
        body: {
          foo: 'bar'
        }
      }, {}, (err, token) => {
        t.error(err)
        const decoded = fastify.jwt.decode(token)
        t.is(decoded.foo, 'bar')
      })
    })
})

test('decode should throw err if no token is passed', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh' })
    .ready(() => {
      try {
        fastify.jwt.decode()
        t.fail()
      } catch (err) {
        t.is(err.message, 'missing token')
      }
    })
})

test('sign should return err if the options are missing', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
      fastify.jwt.sign({}, {}, (err) => {
        t.is(err.message, 'payload is required')
      })
    })
})

test('verify should return err if the token is missing', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
      fastify.jwt.verify({}, {}, (err) => {
        t.is(err.message, 'No Authorization was found in request.headers')
      })
    })
})

test('verify should return format err if ', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })

  t.test('somewhat invalid authorization token is passed', t => {
    t.plan(3)
    fastify.ready(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `Somewhat InvalidToken`
        }
      }, {}, (err, decoded) => {
        t.ok(err)
        t.is(err.message, 'Format is Authorization: Bearer [token]')
        t.notOk(decoded)
      })
    })
  })
  t.test('totall invalid authorization token is passed', t => {
    t.plan(3)
    fastify.ready(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `TotallyInvalidToken`
        }
      }, {}, (err, decoded) => {
        t.ok(err)
        t.is(err.message, 'jwt must be provided')
        t.notOk(decoded)
      })
    })
  })
})

test('verify should return invalid token err if verification fails', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh' })
    .ready(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `Bearer youCant.verify.me`
        }
      }, {}, (err, decoded) => {
        t.is(err.message, 'invalid token')
      })
    })
})
