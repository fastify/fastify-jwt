'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const { createSigner } = require('fast-jwt')
const jwt = require('../jwt')
const defaultExport = require('../jwt').default
const { fastifyJwt: namedExport } = require('../jwt')

const helper = require('./helper')

const passphrase = 'super secret passphrase'
const { privateKey: privateKeyProtected, publicKey: publicKeyProtected } = helper.generateKeyPairProtected(passphrase)
const { privateKey: privateKeyProtectedECDSA, publicKey: publicKeyProtectedECDSA } = helper.generateKeyPairECDSAProtected(passphrase)
const { privateKey, publicKey } = helper.generateKeyPair()
const { privateKey: privateKeyECDSA, publicKey: publicKeyECDSA } = helper.generateKeyPairECDSA()

test('export', async function (t) {
  t.plan(3)

  await t.test('module export', function (t) {
    t.plan(1)
    t.assert.strictEqual(typeof jwt, 'function')
  })

  await t.test('default export', function (t) {
    t.plan(1)
    t.assert.strictEqual(typeof defaultExport, 'function')
  })

  await t.test('named export', function (t) {
    t.plan(1)
    t.assert.strictEqual(typeof namedExport, 'function')
  })
})

test('register', async function (t) {
  t.plan(17)

  await t.test('Expose jwt methods', async function (t) {
    t.plan(8)

    const fastify = Fastify()
    fastify.register(jwt, {
      secret: 'test',
      cookie: {
        cookieName: 'token',
        signed: false
      }
    })

    fastify.get('/methods', function (request, reply) {
      t.assert.ok(request.jwtDecode)
      t.assert.ok(request.jwtVerify)
      t.assert.ok(reply.jwtSign)
      return {}
    })

    await fastify.ready()

    t.assert.ok(fastify.jwt.decode)
    t.assert.ok(fastify.jwt.options)
    t.assert.ok(fastify.jwt.sign)
    t.assert.ok(fastify.jwt.verify)
    t.assert.ok(fastify.jwt.cookie)

    return fastify.inject({
      method: 'get',
      url: '/methods'
    })
  })

  await t.test('secret as an object', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      }
    }).ready()
  })

  await t.test('secret as a Buffer', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: Buffer.from('some secret', 'base64')
    }).ready()
  })

  await t.test('secret as a function with a callback returning a Buffer', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: (_request, _token, callback) => { callback(null, Buffer.from('some secret', 'base64')) }
    }).ready()
  })

  await t.test('secret as a function returning a promise with Buffer', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: () => Promise.resolve(Buffer.from('some secret', 'base64'))
    }).ready()
  })

  await t.test('secret as an async function returning a Buffer', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: async () => Buffer.from('some secret', 'base64')
    }).ready()
  })

  await t.test('deprecated use of options prefix', async function (t) {
    t.plan(1)
    const fastify = Fastify()
    await t.assert.rejects(() => fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      },
      options: { algorithme: 'RS256' }
    }).ready(), undefined, 'options prefix is deprecated')
  })

  await t.test('secret as a malformed object', async function (t) {
    t.plan(2)

    await t.test('only private key (Must return an error)', async function (t) {
      t.plan(1)

      const fastify = Fastify()
      await t.assert.rejects(() => fastify.register(jwt, {
        secret: {
          private: privateKey
        },
        sign: {
          algorithm: 'RS256',
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
        }
      }).ready(), undefined, 'missing public key')
    })

    await t.test('only public key (Must not return an error)', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: {
          public: publicKey
        },
        sign: {
          algorithm: 'ES256',
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
        }
      }).ready()
    })
  })

  await t.test('decode, sign and verify global options (with default HS algorithm)', async function (t) {
    const fastify = Fastify()
    await fastify.register(jwt, {
      secret: 'test',
      decode: { complete: true },
      sign: {
        iss: 'Some issuer',
        sub: 'Some subject',
        aud: 'Some audience'
      },
      verify: {
        allowedIss: 'Some issuer',
        allowedSub: 'Some subject',
        allowedAud: 'Some audience'
      }
    }).ready()
  })

  await t.test('decode, sign and verify global options and secret as an object', async function (t) {
    t.plan(2)

    await t.test('RS algorithm signed certificates', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        decode: { complete: true },
        sign: {
          algorithm: 'RS256',
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
        },
        verify: {
          algorithms: ['RS256'],
          allowedAud: 'Some audience',
          allowedIss: 'Some issuer',
          allowedSub: 'Some subject'
        }
      }).ready()
    })

    await t.test('ES algorithm signed certificates', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: {
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        decode: { complete: true },
        sign: {
          algorithm: 'ES256',
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
        },
        verify: {
          algorithms: ['ES256'],
          allowedAud: 'Some audience',
          allowedIss: 'Some issuer',
          allowedSub: 'Some subject'
        }
      }).ready()
    })
  })

  async function runWithSecret (t, secret) {
    const fastify = Fastify()
    fastify.register(jwt, { secret })

    fastify.post('/sign', async function (request, reply) {
      const token = await reply.jwtSign(request.body)
      return reply.send({ token })
    })

    fastify.get('/verify', function (request) {
      return request.jwtVerify()
    })

    await fastify.ready()

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(decodedToken.foo, 'bar')
  }

  await t.test('secret as a function with callback', t => {
    return runWithSecret(t, function (_request, _token, callback) {
      callback(null, 'some-secret')
    })
  })

  await t.test('secret as a function returning a promise', t => {
    return runWithSecret(t, function () {
      return Promise.resolve('some-secret')
    })
  })

  await t.test('secret as an async function', t => {
    return runWithSecret(t, async function () {
      return 'some-secret'
    })
  })

  await t.test('secret as a function with callback returning a Buffer', t => {
    return runWithSecret(t, function (_request, _token, callback) {
      callback(null, Buffer.from('some-secret', 'base64'))
    })
  })

  await t.test('secret as a function returning a promise with a Buffer', t => {
    return runWithSecret(t, function () {
      return Promise.resolve(Buffer.from('some secret', 'base64'))
    })
  })

  await t.test('secret as an async function returning a Buffer', t => {
    return runWithSecret(t, async function () {
      return Buffer.from('some secret', 'base64')
    })
  })

  await t.test('fail without secret', async function (t) {
    const fastify = Fastify()

    await t.assert.rejects(() => fastify
      .register(jwt)
      .ready(), undefined, 'missing secret')
  })
})

test('sign and verify with HS-secret', async function (t) {
  t.plan(2)

  await t.test('server methods', async function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    await fastify.ready()

    await t.test('synchronous', function (t) {
      t.plan(1)

      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.verify(token)

      t.assert.strictEqual(decoded.foo, 'bar')
    })

    await t.test('with callbacks', function (t) {
      t.plan(3)

      const { promise, resolve } = helper.withResolvers()

      fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
        t.assert.ifError(error)

        fastify.jwt.verify(token, function (error, decoded) {
          t.assert.ifError(error)
          t.assert.strictEqual(decoded.foo, 'bar')
          resolve()
        })
      })
      return promise
    })
  })

  await t.test('route methods', async function (t) {
    t.plan(2)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    fastify.post('/signSync', function (request, reply) {
      return reply.jwtSign(request.body).then(function (token) {
        return { token }
      })
    })

    fastify.get('/verifySync', function (request) {
      return request.jwtVerify()
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

    await fastify.ready()

    await t.test('synchronous', async function (t) {
      t.plan(2)

      const signResponse = await fastify.inject({
        method: 'post',
        url: '/signSync',
        payload: { foo: 'bar' }
      })

      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      const verifyResponse = await fastify.inject({
        method: 'get',
        url: '/verifySync',
        headers: {
          authorization: `Bearer ${token}`
        }
      })

      const decodedToken = JSON.parse(verifyResponse.payload)
      t.assert.strictEqual(decodedToken.foo, 'bar')
    })

    await t.test('with callbacks', async function (t) {
      t.plan(2)

      const signResponse = await fastify.inject({
        method: 'post',
        url: '/signAsync',
        payload: { foo: 'bar' }
      })

      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      const verifyResponse = await fastify.inject({
        method: 'get',
        url: '/verifyAsync',
        headers: {
          authorization: `Bearer ${token}`
        }
      })
      const decodedToken = JSON.parse(verifyResponse.payload)
      t.assert.strictEqual(decodedToken.foo, 'bar')
    })
  })
})

test('sign and verify with RSA/ECDSA certificates and global options', async function (t) {
  t.plan(5)

  await t.test('RSA certificates', async function (t) {
    t.plan(2)

    const config = {
      secret: {
        private: privateKey,
        public: publicKey
      },
      sign: {
        algorithm: 'RS256',
        iss: 'test'
      },
      verify: {
        algorithms: ['RS256'],
        allowedIss: 'test'
      }
    }

    await t.test('server methods', async function (t) {
      t.plan(2)

      let signedToken

      await t.test('signer mode', async function (t) {
        t.plan(2)
        const fastifySigner = Fastify()
        fastifySigner.register(jwt, config)

        await fastifySigner.ready()

        await t.test('synchronous', function (t) {
          t.plan(2)

          signedToken = fastifySigner.jwt.sign({ foo: 'bar' })
          const decoded = fastifySigner.jwt.verify(signedToken)

          t.assert.strictEqual(decoded.foo, 'bar')
          t.assert.strictEqual(decoded.iss, 'test')
        })

        await t.test('with callbacks', function (t) {
          t.plan(4)

          const { promise, resolve } = helper.withResolvers()

          fastifySigner.jwt.sign({ foo: 'bar' }, function (error, token) {
            t.assert.ifError(error)

            fastifySigner.jwt.verify(token, function (error, decoded) {
              t.assert.ifError(error)
              t.assert.strictEqual(decoded.foo, 'bar')
              t.assert.strictEqual(decoded.iss, 'test')
              resolve()
            })
          })

          return promise
        })
      })

      await t.test('verifier mode', async function (t) {
        t.plan(2)
        const fastifyVerifier = Fastify()
        fastifyVerifier.register(jwt, {
          ...config,
          secret: {
            public: config.secret.public
            // no private key
          }
        })

        await fastifyVerifier.ready()

        await t.test('synchronous', function (t) {
          t.plan(3)

          try {
            fastifyVerifier.jwt.sign({ foo: 'baz' })
          } catch (error) {
            t.assert.strictEqual(error.message, 'unable to sign: secret is configured in verify mode')
          }

          const decoded = fastifyVerifier.jwt.verify(signedToken)
          t.assert.strictEqual(decoded.foo, 'bar')
          t.assert.strictEqual(decoded.iss, 'test')
        })

        await t.test('with callbacks', function (t) {
          t.plan(4)

          try {
            fastifyVerifier.jwt.sign({ foo: 'baz' }, function (error) {
              // as for now, verifier-only error is not propagated here
              t.assert.ifError('SHOULD NOT BE HERE')
              t.assert.ifError(error)
            })
          } catch (error) {
            t.assert.strictEqual(error.message, 'unable to sign: secret is configured in verify mode')
          }

          const { promise, resolve } = helper.withResolvers()

          fastifyVerifier.jwt.verify(
            signedToken,
            function (error, decoded) {
              t.assert.ifError(error)
              t.assert.strictEqual(decoded.foo, 'bar')
              t.assert.strictEqual(decoded.iss, 'test')
              resolve()
            }
          )

          return promise
        })
      })
    })

    await t.test('route methods', async function (t) {
      t.plan(2)

      let signedToken

      await t.test('signer mode', async function (t) {
        t.plan(2)

        const fastify = Fastify()
        fastify.register(jwt, config)

        fastify.post('/signSync', function (request, reply) {
          reply.jwtSign(request.body)
            .then(function (token) {
              return reply.send({ token })
            })
        })

        fastify.get('/verifySync', function (request) {
          return request.jwtVerify()
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

        await fastify.ready()

        await t.test('synchronous', async function (t) {
          t.plan(3)

          const signResponse = await fastify.inject({
            method: 'post',
            url: '/signSync',
            payload: { foo: 'bar' }
          })

          const token = JSON.parse(signResponse.payload).token
          t.assert.ok(token)
          signedToken = token

          const verifyResponse = await fastify.inject({
            method: 'get',
            url: '/verifySync',
            headers: {
              authorization: `Bearer ${token}`
            }
          })

          const decodedToken = JSON.parse(verifyResponse.payload)
          t.assert.strictEqual(decodedToken.foo, 'bar')
          t.assert.strictEqual(decodedToken.iss, 'test')
        })

        await t.test('with callbacks', async function (t) {
          t.plan(3)

          const signResponse = await fastify.inject({
            method: 'post',
            url: '/signAsync',
            payload: { foo: 'bar' }
          })

          const token = JSON.parse(signResponse.payload).token
          t.assert.ok(token)

          const verifyResponse = await fastify.inject({
            method: 'get',
            url: '/verifyAsync',
            headers: {
              authorization: `Bearer ${token}`
            }
          })

          const decodedToken = JSON.parse(verifyResponse.payload)
          t.assert.strictEqual(decodedToken.foo, 'bar')
          t.assert.strictEqual(decodedToken.iss, 'test')
        })
      })

      await t.test('verifier mode', async function (t) {
        t.plan(1)
        const fastifyVerifier = Fastify()
        fastifyVerifier.register(jwt, {
          ...config,
          secret: {
            public: config.secret.public
            // no private key
          }
        })

        fastifyVerifier.post('/signSync', function (request, reply) {
          reply.jwtSign(request.body)
            .then(function (token) {
              return reply.send({ token })
            })
        })

        fastifyVerifier.get('/verifySync', function (request) {
          return request.jwtVerify()
        })

        await fastifyVerifier.ready()

        await t.test('synchronous verifier', async function (t) {
          t.plan(4)

          const response = await fastifyVerifier.inject({
            method: 'post',
            url: '/signSync',
            payload: { foo: 'bar' }
          })

          t.assert.strictEqual(response.statusCode, 500)
          const payload = JSON.parse(response.payload)
          t.assert.strictEqual(payload.message, 'unable to sign: secret is configured in verify mode')

          const verifyResponse = await fastifyVerifier.inject({
            method: 'get',
            url: '/verifySync',
            headers: {
              authorization: `Bearer ${signedToken}`
            }
          })

          const decodedToken = JSON.parse(verifyResponse.payload)
          t.assert.strictEqual(decodedToken.foo, 'bar')
          t.assert.strictEqual(decodedToken.iss, 'test')
        })
      })
    })
  })

  await t.test('ECDSA certificates', async function (t) {
    t.plan(2)

    await t.test('server methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        sign: {
          algorithm: 'ES256',
          sub: 'test'
        },
        verify: {
          algorithms: ['ES256'],
          allowedSub: 'test'
        }
      })

      await fastify.ready()

      await t.test('synchronous', function (t) {
        t.plan(2)

        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.verify(token)

        t.assert.strictEqual(decoded.foo, 'bar')
        t.assert.strictEqual(decoded.sub, 'test')
      })

      await t.test('with callbacks', function (t) {
        t.plan(4)

        const { promise, resolve } = helper.withResolvers()

        fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
          t.assert.ifError(error)

          fastify.jwt.verify(token, function (error, decoded) {
            t.assert.ifError(error)
            t.assert.strictEqual(decoded.foo, 'bar')
            t.assert.strictEqual(decoded.sub, 'test')
            resolve()
          })
        })

        return promise
      })
    })

    await t.test('route methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        sign: {
          algorithm: 'ES256',
          sub: 'test'
        },
        verify: {
          allowedSub: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request) {
        return request.jwtVerify()
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

      await fastify.ready()

      await t.test('synchronous', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signSync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifySync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.sub, 'test')
      })

      await t.test('with callbacks', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signAsync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifyAsync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.sub, 'test')
      })
    })
  })

  await t.test('RSA certificates (passphrase protected)', async function (t) {
    t.plan(2)

    await t.test('server methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtected, passphrase: 'super secret passphrase' },
          public: publicKeyProtected
        },
        sign: {
          algorithm: 'RS256',
          aud: 'test'
        },
        verify: {
          allowedAud: 'test'
        }
      })

      await fastify.ready()

      await t.test('synchronous', function (t) {
        t.plan(2)

        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.verify(token)

        t.assert.strictEqual(decoded.aud, 'test')
        t.assert.strictEqual(decoded.foo, 'bar')
      })

      await t.test('with callbacks', function (t) {
        t.plan(4)

        const { promise, resolve } = helper.withResolvers()

        fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
          t.assert.ifError(error)

          fastify.jwt.verify(token, function (error, decoded) {
            t.assert.ifError(error)
            t.assert.strictEqual(decoded.aud, 'test')
            t.assert.strictEqual(decoded.foo, 'bar')
            resolve()
          })
        })

        return promise
      })
    })

    await t.test('route methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtected, passphrase: 'super secret passphrase' },
          public: publicKeyProtected
        },
        sign: {
          algorithm: 'RS256',
          aud: 'test'
        },
        verify: {
          allowedAud: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request) {
        return request.jwtVerify()
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

      await fastify.ready()

      await t.test('synchronous', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signSync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifySync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.aud, 'test')
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })

      await t.test('with callbacks', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signAsync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifyAsync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.aud, 'test')
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })

  await t.test('ECDSA certificates (passphrase protected)', async function (t) {
    t.plan(2)

    await t.test('server methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtectedECDSA, passphrase: 'super secret passphrase' },
          public: publicKeyProtectedECDSA
        },
        sign: {
          algorithm: 'ES256',
          sub: 'test'
        },
        verify: {
          allowedSub: 'test'
        }
      })

      await fastify.ready()

      await t.test('synchronous', function (t) {
        t.plan(2)

        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.verify(token)

        t.assert.strictEqual(decoded.foo, 'bar')
        t.assert.strictEqual(decoded.sub, 'test')
      })

      await t.test('with callbacks', function (t) {
        t.plan(4)

        const { promise, resolve } = helper.withResolvers()

        fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
          t.assert.ifError(error)

          fastify.jwt.verify(token, function (error, decoded) {
            t.assert.ifError(error)
            t.assert.strictEqual(decoded.foo, 'bar')
            t.assert.strictEqual(decoded.sub, 'test')
            resolve()
          })
        })

        return promise
      })
    })

    await t.test('route methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtectedECDSA, passphrase: 'super secret passphrase' },
          public: publicKeyProtectedECDSA
        },
        sign: {
          algorithm: 'ES256',
          sub: 'test'
        },
        verify: {
          allowedSub: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request) {
        return request.jwtVerify()
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

      await fastify.ready()

      await t.test('synchronous', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signSync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifySync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.sub, 'test')
      })

      await t.test('with callbacks', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signAsync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifyAsync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.sub, 'test')
      })
    })
  })

  await t.test('Overriding global options', async function (t) {
    t.plan(2)

    await t.test('server methods', async function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        sign: {
          algorithm: 'RS256',
          iss: 'test'
        },
        verify: {
          algorithms: ['RS256'],
          allowedIss: 'test'
        }
      })

      await fastify.ready()

      await t.test('synchronous', function (t) {
        t.plan(2)
        const localOptions = Object.assign({}, fastify.jwt.options.sign)
        localOptions.iss = 'other'

        const token = fastify.jwt.sign({ foo: 'bar' }, localOptions)
        const decoded = fastify.jwt.verify(token, { iss: 'other' })

        t.assert.strictEqual(decoded.foo, 'bar')
        t.assert.strictEqual(decoded.iss, 'other')
      })

      await t.test('with callbacks', function (t) {
        t.plan(4)
        const localOptions = Object.assign({}, fastify.jwt.options.sign)
        localOptions.iss = 'other'

        const { promise, resolve } = helper.withResolvers()

        fastify.jwt.sign({ foo: 'bar' }, localOptions, function (error, token) {
          t.assert.ifError(error)

          fastify.jwt.verify(token, { iss: 'other' }, function (error, decoded) {
            t.assert.ifError(error)
            t.assert.strictEqual(decoded.foo, 'bar')
            t.assert.strictEqual(decoded.iss, 'other')
            resolve()
          })
        })

        return promise
      })
    })

    await t.test('route methods', async function (t) {
      t.plan(2)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        sign: {
          algorithm: 'RS256',
          iss: 'test'
        },
        verify: {
          allowedIss: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request) {
        return request.jwtVerify()
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

      await fastify.ready()

      await t.test('synchronous', async function (t) {
        t.plan(3)

        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signSync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifySync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.iss, 'test')
      })

      await t.test('with callbacks', async function (t) {
        t.plan(3)
        const signResponse = await fastify.inject({
          method: 'post',
          url: '/signAsync',
          payload: { foo: 'bar' }
        })

        const token = JSON.parse(signResponse.payload).token
        t.assert.ok(token)

        const verifyResponse = await fastify.inject({
          method: 'get',
          url: '/verifyAsync',
          headers: {
            authorization: `Bearer ${token}`
          }
        })

        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
        t.assert.strictEqual(decodedToken.iss, 'test')
      })
    })
  })
})

test('sign and verify with trusted token', async function (t) {
  t.plan(2)
  await t.test('Trusted token verification', async function (t) {
    t.plan(2)

    const f = Fastify()
    f.register(jwt, { secret: 'test', trusted: (_request, { jti }) => jti !== 'untrusted' })
    f.get('/', (request, reply) => {
      request.jwtVerify()
        .then(function (decodedToken) {
          delete decodedToken?.iat
          t.assert.deepStrictEqual(decodedToken, { foo: 'bar', jti: 'trusted' })
          return reply.send(decodedToken)
        })
        .catch(function (error) {
          return reply.send(error)
        })
    })

    const signer = createSigner({ key: 'test', jti: 'trusted' })
    const trustedToken = signer({ foo: 'bar' })
    const response = await f.inject({
      method: 'get',
      url: '/',
      headers: {
        authorization: `Bearer ${trustedToken}`
      }
    })

    t.assert.strictEqual(response.statusCode, 200)
  })

  await t.test('Trusted token - async verification', async function (t) {
    t.plan(2)

    const f = Fastify()
    f.register(jwt, { secret: 'test', trusted: (_request, { jti }) => Promise.resolve(jti !== 'untrusted') })
    f.get('/', (request, reply) => {
      request.jwtVerify()
        .then(function (decodedToken) {
          delete decodedToken?.iat
          t.assert.deepStrictEqual(decodedToken, { foo: 'bar', jti: 'trusted' })
          return reply.send(decodedToken)
        })
        .catch(function (error) {
          return reply.send(error)
        })
    })

    const signer = createSigner({ key: 'test', jti: 'trusted' })
    const trustedToken = signer({ foo: 'bar' })
    const response = await f.inject({
      method: 'get',
      url: '/',
      headers: {
        authorization: `Bearer ${trustedToken}`
      }
    })

    t.assert.strictEqual(response.statusCode, 200)
  })
})

test('decode', async function (t) {
  t.plan(2)

  await t.test('without global options', async function (t) {
    t.plan(2)

    await t.test('without local options', async function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, { secret: 'test' })

      await fastify.ready()

      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.decode(token)
      t.assert.strictEqual(decoded.foo, 'bar')
    })

    await t.test('with local options', async function (t) {
      t.plan(3)

      const fastify = Fastify()
      fastify.register(jwt, { secret: 'test' })

      await fastify.ready()

      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.decode(token, { complete: true })

      t.assert.strictEqual(decoded.header.alg, 'HS256')
      t.assert.strictEqual(decoded.header.typ, 'JWT')
      t.assert.strictEqual(decoded.payload.foo, 'bar')
    })
  })

  await t.test('with global options', async function (t) {
    t.plan(2)

    await t.test('without overriding global options', async function (t) {
      t.plan(3)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        decode: { complete: true }
      })

      await fastify.ready()
      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.decode(token)

      t.assert.strictEqual(decoded.header.alg, 'HS256')
      t.assert.strictEqual(decoded.header.typ, 'JWT')
      t.assert.strictEqual(decoded.payload.foo, 'bar')
    })

    await t.test('overriding global options', async function (t) {
      t.plan(4)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        decode: { complete: true }
      })

      await fastify.ready()
      const token = fastify.jwt.sign({ foo: 'bar' })
      const decoded = fastify.jwt.decode(token, { complete: false })

      t.assert.strictEqual(decoded.header, undefined)
      t.assert.strictEqual(decoded.payload, undefined)
      t.assert.strictEqual(decoded.signature, undefined)
      t.assert.strictEqual(decoded.foo, 'bar')
    })
  })
})

test('errors', async function (t) {
  t.plan(16)

  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'test',
    trusted: (_request, { jti }) => jti !== 'untrusted',
    decode: { checkTyp: 'JWT' }
  })

  fastify.post('/sign', function (request, reply) {
    reply.jwtSign(request.body.payload, { sign: { iss: 'foo' } })
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

  fastify.get('/verifyFailOnIss', function (request, reply) {
    request.jwtVerify({ verify: { allowedIss: 'bar' } })
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verifyFailOnAlgorithmMismatch', function (request, reply) {
    request.jwtVerify({ verify: { algorithms: ['invalid'] } })
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verifyFailOnInvalidClockTimestamp', function (request, reply) {
    request.jwtVerify({ verify: { clockTimestamp: 'not_a_number' } })
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verifyErrorCallbackCount', function (request, reply) {
    let count = 0
    request.jwtVerify({ verify: { key: 'invalid key' } }, function () {
      count += 1
      setImmediate(function () {
        reply.send({ count })
      })
    })
  })

  fastify.get('/verifyFailUntrustedToken', function (request, reply) {
    request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verifyFailUnsignedToken', function (request, reply) {
    request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  await fastify.ready()

  await t.test('no payload error', async function (t) {
    t.plan(1)

    const response = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: null
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'jwtSign requires a payload')
  })

  await t.test('no authorization header error', async function (t) {
    t.plan(2)

    const response = await fastify.inject({
      method: 'get',
      url: '/verify'
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'No Authorization was found in request.headers')
    t.assert.strictEqual(response.statusCode, 401)
  })
  await t.test('no bearer authorization header error', async function (t) {
    t.plan(2)

    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: 'Invalid Format'
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'No Authorization was found in request.headers')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('authorization header malformed error', async function (t) {
    t.plan(2)

    const response = await fastify
      .inject({
        method: 'get',
        url: '/verify',
        headers: {
          authorization: 'Bearer 1.2.3'
        }
      })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: The token header is not a valid base64url serialized JSON.')
  })

  await t.test('authorization header invalid type error', async function (t) {
    t.plan(2)

    const response = await fastify
      .inject({
        method: 'get',
        url: '/verify',
        headers: {
          authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUiJ9.e30.ha5mKb-6aDOVHh5lRaUBNdDmMAYLOl1no3LQkV2mAMQ'
        }
      })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: The type must be "JWT".')
  })

  await t.test('Bearer authorization format error', async function (t) {
    t.plan(2)

    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: 'Bearer Bad Format'
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Format is Authorization: Bearer [token]')
    t.assert.strictEqual(response.statusCode, 400)
  })

  await t.test('Expired token error', async function (t) {
    t.plan(2)

    const expiredToken = fastify.jwt.sign({
      exp: Math.floor(Date.now() / 1000) - 60,
      foo: 'bar'
    })
    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: `Bearer ${expiredToken}`
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Authorization token expired')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('Invalid signature error', async function (t) {
    t.plan(2)

    const signer = createSigner({ key: Buffer.alloc(64) })
    const invalidSignatureToken = signer({ foo: 'bar' })

    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: `Bearer ${invalidSignatureToken}`
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: The token signature is invalid.')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('Untrusted token error', async function (t) {
    t.plan(2)

    const signer = createSigner({ key: 'test', jti: 'untrusted' })
    const untrustedToken = signer({ foo: 'bar' })

    const response = await fastify.inject({
      method: 'get',
      url: '/verifyFailUntrustedToken',
      headers: {
        authorization: `Bearer ${untrustedToken}`
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Untrusted authorization token')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('Untrusted token error - async verification', async function (t) {
    t.plan(2)

    const f = Fastify()
    f.register(jwt, { secret: 'test', trusted: (_request, { jti }) => Promise.resolve(jti !== 'untrusted') })
    f.get('/', (request, reply) => {
      request.jwtVerify()
        .then(function (decodedToken) {
          return reply.send(decodedToken)
        })
        .catch(function (error) {
          return reply.send(error)
        })
    })

    const signer = createSigner({ key: 'test', jti: 'untrusted' })
    const untrustedToken = signer({ foo: 'bar' })
    const response = await f.inject({
      method: 'get',
      url: '/',
      headers: {
        authorization: `Bearer ${untrustedToken}`
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Untrusted authorization token')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('Unsigned token error', async function (t) {
    t.plan(2)

    const signer = createSigner({ algorithm: 'none' })
    const unsignedToken = signer({ foo: 'bar' })

    const response = await fastify.inject({
      method: 'get',
      url: '/verifyFailUnsignedToken',
      headers: {
        authorization: `Bearer ${unsignedToken}`
      }
    })

    const error = JSON.parse(response.payload)
    t.assert.strictEqual(error.message, 'Unsigned authorization token')
    t.assert.strictEqual(response.statusCode, 401)
  })

  await t.test('requestVerify function: steed.waterfall error function loop test', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: { foo: 'bar' }
      }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verifyFailOnIss',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const error = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: The iss claim value is not allowed.')
    t.assert.strictEqual(verifyResponse.statusCode, 401)
  })

  await t.test('requestVerify function: wrap missing required claims', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: { foo: 'bar' }
      }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verifyFailMissingRequiredClaim',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const error = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: The bar claim is required.')
    t.assert.strictEqual(verifyResponse.statusCode, 401)
  })

  await t.test('requestVerify function: algorithm mismatch error', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: { foo: 'bar' }
      }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verifyFailOnAlgorithmMismatch',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const error = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(error.message, 'Authorization token is invalid: Invalid public key provided for algorithms invalid.')
    t.assert.strictEqual(verifyResponse.statusCode, 401)
  })

  await t.test('requestVerify function: invalid timestamp', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: { foo: 'bar' }
      }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verifyFailOnInvalidClockTimestamp',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const error = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(error.message, 'The clockTimestamp option must be a positive number.')
    t.assert.strictEqual(verifyResponse.statusCode, 500)
  })

  await t.test('jwtVerify callback invoked once on error', async function (t) {
    t.plan(2)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: {
        payload: { foo: 'bar' }
      }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const response = await fastify.inject({
      method: 'get',
      url: '/verifyErrorCallbackCount',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const result = JSON.parse(response.payload)
    t.assert.strictEqual(result.count, 1)
  })
})

test('token in a signed cookie, with @fastify/cookie parsing', async function (t) {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'test',
    cookie: { cookieName: 'jwt', signed: true }
  })
  fastify.register(require('@fastify/cookie'), {
    secret: 'cookieSecret'
  })

  fastify.post('/sign', function (request, reply) {
    return reply.jwtSign(request.body)
      .then(function (token) {
        return reply.setCookie('jwt', token, { signed: true }).send({ token })
      })
  })

  fastify.get('/verify', function (request, reply) {
    return request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
  })

  const signResponse = await fastify.inject({
    method: 'post',
    url: '/sign',
    payload: { foo: 'bar' }
  })

  const cookieName = signResponse.cookies[0].name
  const signedCookie = signResponse.cookies[0].value

  t.assert.strictEqual(cookieName, 'jwt')

  const response = await fastify.inject({
    method: 'get',
    url: '/verify',
    cookies: {
      jwt: signedCookie
    }
  })

  const decodedToken = JSON.parse(response.payload)
  t.assert.strictEqual(decodedToken.foo, 'bar')
})

test('token in cookie only, when onlyCookie is passed to verifyJWT()', async function (t) {
  t.plan(4)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', cookie: { cookieName: 'jwt' } })
  fastify.register(require('@fastify/cookie'))

  fastify.post('/sign', function (request, reply) {
    return reply.jwtSign(request.body)
      .then(function (token) {
        return { token }
      })
  })

  fastify.get('/verify', function (request, reply) {
    return request.jwtVerify({ onlyCookie: true })
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
  })

  await t.test('token present in cookie', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })

  await t.test('token absent in cookie', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'get',
      url: '/verify',
      cookies: {}
    }).then(function (verifyResponse) {
      const error = JSON.parse(verifyResponse.payload)
      t.assert.strictEqual(error.message, 'No Authorization was found in request.cookies')
      t.assert.strictEqual(error.statusCode, 401)
    })
  })

  // should reject
  await t.test('authorization headers present but no cookie header. should reject as we only check for cookie header', function (t) {
    t.plan(3)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        headers: {
          authorization: token
        }
      }).then(function (verifyResponse) {
        const error = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(error.message, 'No Authorization was found in request.cookies')
        t.assert.strictEqual(error.statusCode, 401)
      })
    })
  })

  // check here 1
  await t.test('malformed cookie header, should reject', function (t) {
    t.plan(3)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token + 'randomValue'
        }
      }).then(function (verifyResponse) {
        const error = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(error.message, 'Authorization token is invalid: The token signature is invalid.')
        t.assert.strictEqual(error.statusCode, 401)
      })
    })
  })
})

test('token in cookie, with @fastify/cookie parsing', async function (t) {
  t.plan(6)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', cookie: { cookieName: 'jwt' } })
  fastify.register(require('@fastify/cookie'))

  fastify.post('/sign', function (request, reply) {
    return reply.jwtSign(request.body)
      .then(function (token) {
        return { token }
      })
  })

  fastify.get('/verify', function (request, reply) {
    return request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
  })

  await t.test('token present in cookie', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })

  await t.test('token absent in cookie', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'get',
      url: '/verify',
      cookies: {}
    }).then(function (verifyResponse) {
      const error = JSON.parse(verifyResponse.payload)
      t.assert.strictEqual(error.message, 'No Authorization was found in request.cookies')
      t.assert.strictEqual(error.statusCode, 401)
    })
  })

  await t.test('both authorization header and cookie present, both valid', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        },
        headers: {
          authorization: `Bearer ${token}`
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })

  await t.test('both authorization and cookie headers present, cookie token value empty (header fallback)', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: ''
        },
        headers: {
          authorization: `Bearer ${token}`
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })

  await t.test('both authorization and cookie headers present, both values empty', function (t) {
    t.plan(3)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: ''
        },
        headers: {
          authorization: ''
        }
      }).then(function (verifyResponse) {
        const error = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(error.message, 'No Authorization was found in request.cookies')
        t.assert.strictEqual(error.statusCode, 401)
      })
    })
  })

  await t.test('both authorization and cookie headers present, header malformed', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        },
        headers: {
          authorization: 'BearerX'
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })
})

test('token in cookie, without @fastify/cookie parsing', async function (t) {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', cookie: { cookieName: 'jwt' } })

  fastify.post('/sign', function (request, reply) {
    return reply.jwtSign(request.body)
      .then(function (token) {
        return { token }
      })
  })

  fastify.get('/verify', function (request, reply) {
    return request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
  })

  await t.test('token present in cookie, but unparsed', function (t) {
    t.plan(3)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        }
      }).then(function (verifyResponse) {
        const error = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(error.message, 'Cookie could not be parsed in request')
        t.assert.strictEqual(error.statusCode, 400)
      })
    })
  })

  await t.test('both authorization and cookie headers present, cookie unparsed (header fallback)', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        },
        headers: {
          authorization: `Bearer ${token}`
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.assert.strictEqual(decodedToken.foo, 'bar')
      })
    })
  })
})

test('token and refreshToken in a signed cookie, with @fastify/cookie parsing, decoded with different payloads ', function (t) {
  t.plan(3)

  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'test',
    cookie: { cookieName: 'refreshToken', signed: true }
  })

  fastify.register(require('@fastify/cookie'), {
    secret: 'cookieSecret'
  })

  fastify.post('/sign', async function (request, reply) {
    const { token, refreshToken } = request.body
    const tokenSigned = await reply.jwtSign(token, { expiresIn: '10m' })
    const refreshTokenSigned = await reply.jwtSign(refreshToken, { expiresIn: '1d' })
    return reply.setCookie('refreshToken', refreshTokenSigned, { signed: true }).send({ tokenSigned })
  })

  fastify.get('/verify', async function (request, reply) {
    const token = await request.jwtVerify()
    const refreshToken = await request.jwtVerify({ onlyCookie: true })
    return reply.send({ token, refreshToken })
  })

  return fastify.inject({
    method: 'post',
    url: '/sign',
    payload: { token: { foo: 'bar' }, refreshToken: { bar: 'foo' } }
  }).then(async function (signResponse) {
    const cookieName = signResponse.cookies[0].name
    const signedCookie = signResponse.cookies[0].value

    const payLoad = JSON.parse(signResponse.payload)
    const signedTokenHeader = payLoad.tokenSigned

    t.assert.strictEqual(cookieName, 'refreshToken')

    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      cookies: {
        refreshToken: signedCookie
      },
      headers: {
        Authorization: 'Bearer ' + signedTokenHeader
      }
    })

    const decodedToken = JSON.parse(response.payload)

    t.assert.strictEqual(decodedToken.token.foo, 'bar')
    t.assert.strictEqual(decodedToken.refreshToken.bar, 'foo')
  })
})

test('custom response messages', function (t) {
  t.plan(6)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', messages: { noAuthorizationInHeaderMessage: 'auth header missing', authorizationTokenExpiredMessage: 'token expired', authorizationTokenInvalid: 'invalid token', authorizationTokenUntrusted: 'untrusted token', authorizationTokenUnsigned: 'unsigned token' }, trusted: (_request, { jti }) => jti !== 'untrusted' })

  fastify.get('/verify', function (request, reply) {
    request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  return fastify
    .ready()
    .then(async function () {
      await t.test('custom no authorization header error', function (t) {
        t.plan(2)

        return fastify.inject({
          method: 'get',
          url: '/verify'
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'auth header missing')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })

      await t.test('fallback authorization header format error', function (t) {
        t.plan(2)

        return fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: 'Invalid Format'
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'auth header missing')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })

      await t.test('custom expired token error', function (t) {
        t.plan(2)

        const expiredToken = fastify.jwt.sign({
          exp: Math.floor(Date.now() / 1000) - 60,
          foo: 'bar'
        })
        return fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${expiredToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'token expired')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })

      await t.test('custom invalid signature error', function (t) {
        t.plan(2)

        const signer = createSigner({ key: Buffer.alloc(64) })
        const invalidSignatureToken = signer({ foo: 'bar' })

        return fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${invalidSignatureToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'invalid token')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })

      await t.test('custom unsigned token error', function (t) {
        t.plan(2)

        const signer = createSigner({ algorithm: 'none' })
        const unsignedToken = signer({ foo: 'bar' })

        return fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${unsignedToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'unsigned token')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })

      await t.test('custom untrusted token error', function (t) {
        t.plan(2)

        const signer = createSigner({ key: 'test', jti: 'untrusted' })
        const untrustedToken = signer({ foo: 'bar' })
        return fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${untrustedToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.assert.strictEqual(error.message, 'untrusted token')
          t.assert.strictEqual(response.statusCode, 401)
        })
      })
    })
})

test('extract custom token', async function (t) {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', verify: { extractToken: (request) => request.headers.customauthheader } })

  fastify.post('/sign', function (request, reply) {
    return reply.jwtSign(request.body)
      .then(function (token) {
        return { token }
      })
  })

  fastify.get('/verify', function (request, reply) {
    return request.jwtVerify()
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
  })

  await t.test('token can be extracted correctly', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        headers: {
          customauthheader: token
        }
      }).then(function (verifyResponse) {
        t.assert.strictEqual(verifyResponse.statusCode, 200)
      })
    })
  })

  await t.test('token can not be extracted', function (t) {
    t.plan(2)
    return fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.assert.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify'
      }).then(function (verifyResponse) {
        t.assert.strictEqual(verifyResponse.statusCode, 400)
      })
    })
  })
})

test('format user', async function (t) {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', formatUser: (payload) => ({ baz: payload.foo }) })

  fastify.post('/sign', async function (request, reply) {
    const token = await reply.jwtSign(request.body)
    return { token }
  })

  fastify.get('/check-decoded-token', async function (request, reply) {
    const decodedToken = await request.jwtVerify()
    return reply.send(decodedToken)
  })

  fastify.get('/check-user', async function (request, reply) {
    await request.jwtVerify()
    return reply.send(request.user)
  })

  await t.test('result of jwtVerify is the result of formatUser', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const response = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const user = JSON.parse(response.payload)
    t.assert.strictEqual(user.foo, undefined)
    t.assert.strictEqual(user.baz, 'bar')
  })

  await t.test('user is set to the result of formatUser', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const response = await fastify.inject({
      method: 'get',
      url: '/check-user',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const user = JSON.parse(response.payload)
    t.assert.strictEqual(user.foo, undefined)
    t.assert.strictEqual(user.baz, 'bar')
  })
})

test('expose decode token for plugin extension', async function (t) {
  t.plan(3)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test' })

  fastify.post('/sign', async function (request, reply) {
    const token = await reply.jwtSign(request.body)
    return { token }
  })

  fastify.get('/check-decoded-token', async function (request, reply) {
    const decodedToken = await request.jwtDecode()
    return reply.send(decodedToken)
  })

  fastify.get('/check-decoded-token-callback', function (request, reply) {
    request.jwtDecode((err, decodedToken) => {
      if (err) {
        return reply.send(err)
      }
      return reply.send(decodedToken)
    })
  })

  await t.test('should decode token without verifying', async function (t) {
    t.plan(2)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.assert.strictEqual(decodedToken.foo, 'bar')
  })

  await t.test('should decode token with callback', async function (t) {
    t.plan(2)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token-callback',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.assert.strictEqual(decodedToken.foo, 'bar')
  })

  await t.test('should handle decode error', async function (t) {
    t.plan(1)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {}
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.assert.strictEqual(decodedToken.statusCode, 401)
  })
})

test('support extended config contract', async function (t) {
  t.plan(1)
  const extConfig = {
    sign: {
      key: 'secret',
      iss: 'api.example.tld'
    },
    verify: {
      key: 'secret',
      allowedIss: 'api.example.tld',
      extractToken: (req) => (req.headers.otherauth)
    },
    decode: {
      complete: true
    }
  }

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test' })

  fastify.post('/sign', async function (request, reply) {
    const token = await reply.jwtSign(request.body, extConfig)
    return { token }
  })

  fastify.get('/check-decoded-token', async function (request, reply) {
    const decodedToken = await request.jwtDecode(extConfig)
    return reply.send(decodedToken)
  })

  fastify.get('/check-verify-token', async function (request, reply) {
    const decodedAndVerifiedToken = await request.jwtVerify(extConfig)
    return reply.send(decodedAndVerifiedToken)
  })

  await t.test('configuration overrides properly passed through callable methods', async function (t) {
    t.plan(7)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        otherauth: token
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.assert.ok(decodedToken)
    t.assert.strictEqual(decodedToken.header.typ, 'JWT')
    t.assert.strictEqual(decodedToken.payload.iss, extConfig.sign.iss)
    t.assert.strictEqual(decodedToken.payload.foo, 'bar')

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/check-verify-token',
      headers: {
        otherauth: token
      }
    })
    const decodedAndVerifiedToken = JSON.parse(verifyResponse.payload)
    t.assert.strictEqual(decodedAndVerifiedToken.iss, extConfig.sign.iss)
    t.assert.strictEqual(decodedAndVerifiedToken.foo, 'bar')
  })
})

test('support fast-jwt compatible config options', async function (t) {
  t.plan(4)
  const options = {
    sign: {
      key: 'secret'
    },
    verify: {
      key: 'secret'
    },
    decode: {
      complete: true
    }
  }

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', ...options })

  fastify.post('/signWithSignOptions', async function (request, reply) {
    const token = await reply.jwtSign(request.body, { sign: { iss: 'foo' } })
    return reply.send({ token })
  })

  fastify.post('/signWithOptions', async function (request, reply) {
    const token = await reply.jwtSign(request.body, { iss: 'foo' })
    return reply.send({ token })
  })

  await fastify.ready()

  await t.test('options are functions', function (t) {
    t.plan(4)
    fastify.jwt.sign({ foo: 'bar' }, (err, token) => {
      t.assert.ifError(err)
      t.assert.ok(token)

      fastify.jwt.verify(token, (err, result) => {
        t.assert.ifError(err)
        t.assert.ok(result)
      })
    })
  })

  await t.test('no options defined', async function (t) {
    const token = await fastify.jwt.sign({ foo: 'bar' })
    t.assert.ok(token)

    const verifiedToken = await fastify.jwt.verify(token)
    t.assert.ok(verifiedToken)
  })

  await t.test('options.sign defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithSignOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)
  })

  await t.test('general options defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)
  })
})

test('supporting time definitions for "maxAge", "expiresIn" and "notBefore"', async function (t) {
  t.plan(4)

  const options = {
    sign: {
      key: 'secret',
      expiresIn: '1d'
    },
    verify: {
      key: 'secret',
      maxAge: 2000
    },
    decode: {
      complete: true
    }
  }

  const oneDayInSeconds = 24 * 60 * 60

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', ...options })

  fastify.post('/signWithSignOptions', async function (request, reply) {
    const token = await reply.jwtSign(request.body, { sign: { iss: 'foo' } })
    return reply.send({ token })
  })

  fastify.post('/signWithOptions', async function (request, reply) {
    const token = await reply.jwtSign(request.body, { iss: 'foo', notBefore: '5 hours' })
    return reply.send({ token })
  })

  fastify.get('/check-decoded-token', async function (request, reply) {
    const decodedToken = await request.jwtDecode()
    return reply.send(decodedToken)
  })

  await fastify.ready()

  await t.test('initial options should not be modified', function (t) {
    t.plan(2)

    t.assert.strictEqual(fastify.jwt.options.sign.expiresIn, '1d')
    t.assert.strictEqual(fastify.jwt.options.verify.maxAge, 2000)
  })

  await t.test('options are functions', function (t) {
    t.plan(7)
    fastify.jwt.sign({ foo: 'bar' }, (err, token) => {
      t.assert.ifError(err)
      t.assert.ok(token)

      fastify.jwt.verify(token, (err, result) => {
        t.assert.ifError(err)
        t.assert.ok(result)
        t.assert.ok(result.exp)
        t.assert.strictEqual(typeof result.exp, 'number')
        t.assert.strictEqual(result.exp - result.iat, oneDayInSeconds)
      })
    })
  })

  await t.test('options.sign defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithSignOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)
    fastify.jwt.verify(token, { secret: 'test' }, (err, result) => {
      t.assert.ifError(err)
      t.assert.ok(result)
      t.assert.ok(result.exp)
      t.assert.strictEqual(typeof result.exp, 'number')
      t.assert.strictEqual(result.iss, 'foo')
      t.assert.strictEqual(result.exp - result.iat, oneDayInSeconds)
    })
  })

  await t.test('general options defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.assert.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        authorization: `Bearer ${token}`
      }
    })

    const decodedToken = JSON.parse(decodeResponse.payload)
    t.assert.ok(decodedToken)
    t.assert.ok(decodedToken.payload.exp)
    t.assert.strictEqual(typeof decodedToken.payload.exp, 'number')
    t.assert.strictEqual(decodedToken.payload.exp - decodedToken.payload.iat, oneDayInSeconds)
    t.assert.ok(decodedToken.payload.nbf)
    t.assert.strictEqual(typeof decodedToken.payload.nbf, 'number')
  })
})

test('global user options should not be modified', async function (t) {
  t.plan(3)

  const options = {
    sign: {
      key: 'secret',
      expiresIn: '1d',
      notBefore: '4 hours'
    },
    verify: {
      key: 'secret',
      maxAge: 2000
    },
    decode: {
      complete: true
    }
  }

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', ...options })

  await fastify.ready()

  t.assert.strictEqual(fastify.jwt.options.sign.expiresIn, '1d')
  t.assert.strictEqual(fastify.jwt.options.sign.notBefore, '4 hours')
  t.assert.strictEqual(fastify.jwt.options.verify.maxAge, 2000)
})

test('decorator name should work after being changed in the options', async function (t) {
  t.plan(5)

  const fastify = Fastify()
  const decoratorName = 'customName'
  fastify.register(jwt, { secret: 'test', decoratorName })

  fastify.post('/sign', async function (request, reply) {
    const token = await reply.jwtSign(request.body)
    return { token }
  })
  fastify.get('/check-user', async function (request, reply) {
    await request.jwtVerify()
    return reply.send(request[decoratorName])
  })

  const signResponse = await fastify.inject({
    method: 'post',
    url: '/sign',
    payload: { foo: 'bar' }
  })
  const token = JSON.parse(signResponse.payload).token
  t.assert.ok(token)
  t.assert.ok(fastify.jwt.options.decoratorName)
  t.assert.strictEqual(fastify.jwt.options.decoratorName, decoratorName)

  const response = await fastify.inject({
    method: 'get',
    url: '/check-user',
    headers: {
      authorization: `Bearer ${token}`
    }
  })
  const user = JSON.parse(response.payload)
  t.assert.strictEqual(user.baz, undefined)
  t.assert.strictEqual(user.foo, 'bar')
})

test('local sign options should not overwrite global sign options', async function (t) {
  t.plan(2)

  const options = {
    secret: 'test',
    sign: {
      expiresIn: '15m'
    }
  }

  const fastify = Fastify()
  fastify.register(jwt, options)

  const tokensDifference = 85500

  fastify.post('/sign', async function (request, reply) {
    const { token, refreshToken } = request.body
    const refreshTokenSigned = await reply.jwtSign(refreshToken, { expiresIn: '1d' })
    const tokenSigned = await reply.jwtSign(token)
    return reply.send({ tokenSigned, refreshTokenSigned })
  })

  await fastify.ready()

  const signResponse = await fastify.inject({
    method: 'post',
    url: '/sign',
    payload: { token: { foo: 'bar' }, refreshToken: { bar: 'foo' } }
  })

  const token = JSON.parse(signResponse.payload).tokenSigned
  const refreshToken = JSON.parse(signResponse.payload).refreshTokenSigned
  const decodedToken = fastify.jwt.verify(token)
  const decodedRefreshToken = fastify.jwt.verify(refreshToken)
  const calculatedDifference = decodedRefreshToken.exp - decodedToken.exp
  // max 5 seconds of difference for safety
  t.assert.ok(calculatedDifference >= tokensDifference && calculatedDifference <= tokensDifference + 5)

  t.assert.strictEqual(fastify.jwt.options.sign.expiresIn, '15m')
})
