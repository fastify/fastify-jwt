'use strict'

const fs = require('fs')
const path = require('path')
const test = require('tap').test
const Fastify = require('fastify')

const jwt = require('./jwt')

const publicKey = fs.readFileSync(`${path.join(__dirname, 'certs')}/public.key`, 'utf8')
const privateKey = fs.readFileSync(`${path.join(__dirname, 'certs')}/private.key`, 'utf8')

const publicKeyProtected = fs.readFileSync(`${path.join(__dirname, 'certs')}/public.pem`)
// passphrase used to protect the private key: super secret passphrase
const privateKeyProtected = fs.readFileSync(`${path.join(__dirname, 'certs')}/private.pem`)

test('register', function (t) {
  t.plan(7)

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

  t.test('secret as an object', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: {
        private: privateKeyProtected,
        public: 'super secret passphrase'
      }
    }).ready(function (error) {
      t.is(error, null)
    })
  })

  t.test('options as an object with default HS algorithm', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: 'test',
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience'
      }
    }).ready(function (error) {
      t.is(error, null)
    })
  })

  t.test('options and secret as an object with RS algorithm', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      },
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    }).ready(function (error) {
      t.is(error, null)
    })
  })

  t.test('secret as string, options as an object with RS algorithm', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: 'test',
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    }).ready(function (error) {
      t.is(error.message, 'RSA Signatures set as Algorithm in the options require a key and passphrase to be set as the secret')
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

test('sign and verify with HS-secret', function (t) {
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
      return reply.jwtSign(request.body).then(function (token) {
        return { token }
      })
    })

    fastify.get('/verifySync', function (request, reply) {
      return request.jwtVerify().then(function (decodedToken) {
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

test('sign and verify with RSA and options', function (t) {
  t.plan(2)

  t.test('server methods', function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      },
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    })

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
    fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      },
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    })

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

test('sign and verify with RSA passphrase protected private key (PEM file) and options', function (t) {
  t.plan(2)

  t.test('server methods', function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, {
      secret: {
        private: { key: privateKeyProtected, passphrase: 'super secret passphrase' },
        public: publicKeyProtected
      },
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    })

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
    fastify.register(jwt, {
      secret: {
        private: { key: privateKeyProtected, passphrase: 'super secret passphrase' },
        public: publicKeyProtected
      },
      options: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience',
        algorithm: 'RS256'
      }
    })

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
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify'
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.is(error.message, 'No Authorization was found in request.headers')
          t.is(response.statusCode, 401)
        })
      })

      t.test('authorization header format error', function (t) {
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: 'Invalid Format'
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.is(error.message, 'Format is Authorization: Bearer [token]')
          t.is(response.statusCode, 400)
        })
      })
    })
})
