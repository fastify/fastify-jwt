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

test('secretCallback should not be wrapped if secret option is a function', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: (req, res, cb) => {
      cb(null, 'superSecretFunction')
    } }, t.error)
    .after(() => {
      fastify.jwt.secretCallback({}, {}, (err, secret) => {
        t.error(err)
        t.is(secret, 'superSecretFunction')
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
  fastify.register(jwt, {}, err => {
    t.is(err.message, 'missing secret')
  })
})

test('sign should return err if the options are missing', t => {
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
        t.is(err.message, 'No authorization token was found')
      })
    })
})

test('verify should return format err if ', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' }, t.error)

  t.test('somewhat invalid authorization token is passed', t => {
    t.plan(3)
    fastify.after(() => {
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
    fastify.after(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `TotallyInvalidToken`
        }
      }, {}, (err, decoded) => {
        t.ok(err)
        t.is(err.message, 'Format is Authorization: Bearer [token]')
        t.notOk(decoded)
      })
    })
  })
})

test('verify should return invalid token err if verification fails', t => {
  t.plan(2)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh' }, t.error)
    .after(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `Bearer youCant.verify.me`
        }
      }, {}, (err, decoded) => {
        t.is(err.message, 'invalid token')
      })
    })
})

test('verify should return null if credentialsRequired is false and', t => {
  t.plan(3)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh', credentialsRequired: false }, t.error)

  t.test('no token is provided', t => {
    t.plan(2)
    fastify.after(() => {
      fastify.jwt.verify({
        headers: {
          authorization: `invalid token`
        }
      }, {}, (err, decoded) => {
        t.error(err)
        t.notOk(decoded)
      })
    })
  })

  t.test('an invalid token is provided', t => {
    t.plan(2)
    fastify.after(() => {
      fastify.jwt.verify({}, {}, (err, decoded) => {
        t.error(err)
        t.notOk(decoded)
      })
    })
  })
})

test('sign and verify should write result to resultProperty when specified', t => {
  t.plan(8)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'superSecret', resultProperty: 'foobar' }, t.error)
    .after(() => {
      let result = {}
      fastify.jwt.sign({
        body: {
          hello: 'world'
        }
      }, result, (err, token) => {
        t.error(err)
        t.ok(token)
        t.ok(result.foobar)
        t.is(result.foobar, token)
        fastify.jwt.verify({
          headers: {
            authorization: `Bearer ${token}`
          }
        }, result, (err, payload) => {
          t.error(err)
          t.equal(payload.hello, 'world')
          t.is(result.foobar.hello, 'world')
        })
      })
    })
})
