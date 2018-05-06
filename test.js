'use strict'

const test = require('tap').test
const Fastify = require('fastify')

const jwt = require('./jwt')

test('register', function (t) {
  t.plan(3)

  t.test('expose jwt methods', function (t) {
    t.plan(6)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    fastify.get('/methods', function (request, reply) {
      t.ok(request.jwtVerify)
      t.ok(reply.jwtSign)
    })

    fastify.ready(function () {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.secret)
    })

    fastify.inject({
      method: 'get',
      url: '/methods'
    })
  })

  t.test('secret as a function', function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, {
      secret: function (request, reply, callback) {
        callback(null, 'some-secret')
      }
    })

    fastify.post('/sign', function (request, reply) {
      reply.jwtSign(request.body)
        .then(function (token) {
          return reply.send({ token })
        })
    })

    fastify.get('/verify', function (request, reply) {
      request.jwtVerify()
        .then(function (decodedToken) {
          return reply.send(decodedToken)
        })
    })

    fastify
      .ready()
      .then(function () {
        fastify.inject({
          method: 'post',
          url: '/sign',
          payload: { foo: 'bar' }
        }).then(function (signResponse) {
          const token = JSON.parse(signResponse.payload).token
          t.ok(token)

          fastify.inject({
            method: 'get',
            url: '/verify',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (verifyResponse) {
            const decodedToken = JSON.parse(verifyResponse.payload)
            t.is(decodedToken.foo, 'bar')
          })
        })
      })
  })

  t.test('fail without secret', function (t) {
    t.plan(1)

    const fastify = Fastify()

    fastify
      .register(jwt)
      .ready(function (error) {
        t.is(error.message, 'missing secret')
      })
  })
})

test('sign and verify', function (t) {
  t.plan(2)

  t.test('server methods', function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    fastify
      .ready()
      .then(function () {
        t.test('synchronous', function (t) {
          t.plan(1)

          const token = fastify.jwt.sign({ foo: 'bar' })
          const decoded = fastify.jwt.verify(token)

          t.is(decoded.foo, 'bar')
        })

        t.test('with callbacks', function (t) {
          t.plan(3)

          fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
            t.error(error)

            fastify.jwt.verify(token, function (error, decoded) {
              t.error(error)
              t.is(decoded.foo, 'bar')
            })
          })
        })
      })
  })

  t.test('route methods', function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    fastify.post('/signSync', function (request, reply) {
      reply.jwtSign(request.body)
        .then(function (token) {
          return reply.send({ token })
        })
    })

    fastify.get('/verifySync', function (request, reply) {
      request.jwtVerify()
        .then(function (decodedToken) {
          return reply.send(decodedToken)
        })
    })

    fastify.post('/signAsync', function (request, reply) {
      reply.jwtSign(request.body, function (error, token) {
        return reply.send(error || { token })
      })
    })

    fastify.get('/verifyAsync', function (request, reply) {
      request.jwtVerify(function (error, decodedToken) {
        return reply.send(error || decodedToken)
      })
    })

    fastify
      .ready()
      .then(function () {
        t.test('synchronous', function (t) {
          t.plan(2)

          fastify.inject({
            method: 'post',
            url: '/signSync',
            payload: { foo: 'bar' }
          }).then(function (signResponse) {
            const token = JSON.parse(signResponse.payload).token
            t.ok(token)

            fastify.inject({
              method: 'get',
              url: '/verifySync',
              headers: {
                authorization: `Bearer ${token}`
              }
            }).then(function (verifyResponse) {
              const decodedToken = JSON.parse(verifyResponse.payload)
              t.is(decodedToken.foo, 'bar')
            })
          })
        })

        t.test('with callbacks', function (t) {
          t.plan(2)

          fastify.inject({
            method: 'post',
            url: '/signAsync',
            payload: { foo: 'bar' }
          }).then(function (signResponse) {
            const token = JSON.parse(signResponse.payload).token
            t.ok(token)

            fastify.inject({
              method: 'get',
              url: '/verifyAsync',
              headers: {
                authorization: `Bearer ${token}`
              }
            }).then(function (verifyResponse) {
              const decodedToken = JSON.parse(verifyResponse.payload)
              t.is(decodedToken.foo, 'bar')
            })
          })
        })
      })
  })
})

test('decode', function (t) {
  t.plan(1)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test' })

  fastify.ready(function () {
    const token = fastify.jwt.sign({ foo: 'bar' })
    const decoded = fastify.jwt.decode(token)
    t.is(decoded.foo, 'bar')
  })
})

test('errors', function (t) {
  t.plan(3)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test' })

  fastify.post('/sign', function (request, reply) {
    reply.jwtSign(request.body.payload)
      .then(function (token) {
        return reply.send({ token })
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verify', function (request, reply) {
    request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify
    .ready()
    .then(function () {
      t.test('no payload error', function (t) {
        t.plan(1)

        fastify.inject({
          method: 'post',
          url: '/sign',
          payload: {
            payload: null
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.is(error.message, 'jwtSign requires a payload')
        })
      })

      t.test('no authorization header error', function (t) {
        t.plan(1)

        fastify.inject({
          method: 'get',
          url: '/verify'
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.is(error.message, 'No Authorization was found in request.headers')
        })
      })

      t.test('authorization header format error', function (t) {
        t.plan(1)

        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: 'Invalid Format'
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.is(error.message, 'Format is Authorization: Bearer [token]')
        })
      })
    })
})
