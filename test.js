'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const rp = require('request-promise-native')
const jwt = require('./jwt')

test('fastify-jwt should expose jwt methods', t => {
  t.plan(8)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(() => {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.secret)
    })
  fastify.get('/test', function (request, reply) {
    t.ok(request.jwtVerify)
    t.ok(reply.jwtSign)
    reply.send({ foo: 'bar' })
  })
  fastify.listen(0, err => {
    fastify.server.unref()
    t.error(err)
    rp({
      method: 'GET',
      uri: `http://localhost:${fastify.server.address().port}/test`,
      json: true
    })
      .then(response => t.ok(response))
      .catch(err => t.fail(err))
  })
})

test('fastify-jwt fails without secret', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt)
    .listen(0, err => t.is(err.message, 'missing secret'))
})

test('sign and verify', t => {
  t.plan(7)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })

  fastify.post('/sign', function (request, reply) {
    reply.jwtSign(request.body.payload, function (err, token) {
      if (err) { return reply.send(err) }
      return reply.send({token})
    })
  })

  fastify.get('/verify', function (request, reply) {
    request.jwtVerify(function (err, decoded) {
      if (err) { return reply.send(err) }
      return reply.send(decoded)
    })
  })

  fastify.listen(0, err => {
    fastify.server.unref()
    t.error(err)
  })

  t.test('syncronously', t => {
    t.plan(1)
    fastify.ready(() => {
      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.verify(token)
      t.is(decoded.foo, 'bar')
    })
  })

  t.test('asynchronously', t => {
    t.plan(5)
    fastify.ready(() => {
      fastify.jwt.sign({ foo: 'bar' }, (err, token) => {
        t.error(err)
        t.ok(token)
        fastify.jwt.verify(token, (err, decoded) => {
          t.error(err)
          t.ok(decoded)
          t.is(decoded.foo, 'bar')
        })
      })
    })
  })

  t.test('jwtSign and jwtVerify', async t => {
    t.plan(3)
    try {
      const sign = await rp({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          payload: {
            foo: 'bar'
          }
        },
        uri: `http://localhost:${fastify.server.address().port}/sign`,
        json: true
      })
      t.ok(sign)
      const verify = await rp({
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          authorization: `Bearer ${sign.token}`
        },
        uri: `http://localhost:${fastify.server.address().port}/verify`,
        json: true
      })
      t.ok(verify)
      t.is(verify.foo, 'bar')
    } catch (err) {
      t.fail(err)
    }
  })

  t.test('jwtVerify throws No Authorization error', async t => {
    t.plan(1)
    try {
      await rp({
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        },
        uri: `http://localhost:${fastify.server.address().port}/verify`,
        json: true
      })
      t.fail()
    } catch ({error}) {
      t.is(error.message, 'No Authorization was found in request.headers')
    }
  })

  t.test('jwtVerify throws Authorization Format error', async t => {
    t.plan(1)
    try {
      await rp({
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Invalid TokenFormat'
        },
        uri: `http://localhost:${fastify.server.address().port}/verify`,
        json: true
      })
      t.fail()
    } catch ({error}) {
      t.is(error.message, 'Format is Authorization: Bearer [token]')
    }
  })

  t.test('jwtSign throws payload error', async t => {
    t.plan(1)
    try {
      await rp({
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          notAPayload: 'sorry'
        }),
        uri: `http://localhost:${fastify.server.address().port}/sign`,
        json: true
      })
      t.fail()
    } catch ({error}) {
      t.is(error.message, 'jwtSign requires a payload')
    }
  })
})

test('decode', t => {
  t.plan(1)
  const fastify = Fastify()
  fastify
    .register(jwt, { secret: 'shh' })
    .ready(() => {
      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.decode(token)
      t.is(decoded.foo, 'bar')
    })
})
// test('secretCallback should not be wrapped if secret option is a function', t => {
//   t.plan(2)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: (req, res, cb) => {
//       cb(null, 'superSecretFunction')
//     } })
//     .ready(() => {
//       fastify.jwt.secretCallback({}, {}, (err, secret) => {
//         t.error(err)
//         t.is(secret, 'superSecretFunction')
//       })
//     })
// })

// test('sign and verify', t => {
//   t.plan(4)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'supersecret' })
//     .ready(() => {
//       fastify.jwt.sign({
//         body: {
//           hello: 'world'
//         }
//       }, {}, (err, token) => {
//         t.error(err)
//         t.ok(token)
//         fastify.jwt.verify({
//           headers: {
//             authorization: `Bearer ${token}`
//           }
//         }, {}, (err, payload) => {
//           t.error(err)
//           t.equal(payload.hello, 'world')
//         })
//       })
//     })
// })
// test('should throw if no secret is given as option', t => {
//   t.plan(1)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, {})
//     .ready(err => {
//       t.is(err.message, 'missing secret')
//     })
// })

// test('decode', t => {
//   t.plan(2)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'shh' })
//     .ready(() => {
//       fastify.jwt.sign({
//         body: {
//           foo: 'bar'
//         }
//       }, {}, (err, token) => {
//         t.error(err)
//         const decoded = fastify.jwt.decode(token)
//         t.is(decoded.foo, 'bar')
//       })
//     })
// })

// test('decode should throw err if no token is passed', t => {
//   t.plan(1)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'shh' })
//     .ready(() => {
//       try {
//         fastify.jwt.decode()
//         t.fail()
//       } catch (err) {
//         t.is(err.message, 'missing token')
//       }
//     })
// })

// test('sign should return err if the options are missing', t => {
//   t.plan(1)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'supersecret' })
//     .ready(() => {
//       fastify.jwt.sign({}, {}, (err) => {
//         t.is(err.message, 'payload is required')
//       })
//     })
// })

// test('verify should return err if the token is missing', t => {
//   t.plan(1)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'supersecret' })
//     .ready(() => {
//       fastify.jwt.verify({}, {}, (err) => {
//         t.is(err.message, 'No Authorization was found in request.headers')
//       })
//     })
// })

// test('verify should return format err if ', t => {
//   t.plan(2)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'supersecret' })

//   t.test('somewhat invalid authorization token is passed', t => {
//     t.plan(3)
//     fastify.ready(() => {
//       fastify.jwt.verify({
//         headers: {
//           authorization: `Somewhat InvalidToken`
//         }
//       }, {}, (err, decoded) => {
//         t.ok(err)
//         t.is(err.message, 'Format is Authorization: Bearer [token]')
//         t.notOk(decoded)
//       })
//     })
//   })
//   t.test('totall invalid authorization token is passed', t => {
//     t.plan(3)
//     fastify.ready(() => {
//       fastify.jwt.verify({
//         headers: {
//           authorization: `TotallyInvalidToken`
//         }
//       }, {}, (err, decoded) => {
//         t.ok(err)
//         t.is(err.message, 'jwt must be provided')
//         t.notOk(decoded)
//       })
//     })
//   })
// })

// test('verify should return invalid token err if verification fails', t => {
//   t.plan(1)
//   const fastify = Fastify()
//   fastify
//     .register(jwt, { secret: 'shh' })
//     .ready(() => {
//       fastify.jwt.verify({
//         headers: {
//           authorization: `Bearer youCant.verify.me`
//         }
//       }, {}, (err, decoded) => {
//         t.is(err.message, 'invalid token')
//       })
//     })
// })
