'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const rawJwt = require('jsonwebtoken')
const jwt = require('../jwt')

const helper = require('./helper')

const passphrase = 'super secret passphrase'
const { privateKey, publicKey } = helper.generateKeyPair()
const { privateKey: privateKeyProtected, publicKey: publicKeyProtected } = helper.generateKeyPairProtected(passphrase)
const { privateKey: privateKeyECDSA, publicKey: publicKeyECDSA } = helper.generateKeyPairECDSA()
const { privateKey: privateKeyProtectedECDSA, publicKey: publicKeyProtectedECDSA } = helper.generateKeyPairECDSAProtected(passphrase)

test('register', function (t) {
  t.plan(14)

  t.test('Expose jwt methods', function (t) {
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
      t.notOk(request.jwtDecode)
      t.ok(request.jwtVerify)
      t.ok(reply.jwtSign)
    })

    fastify.ready(function () {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.options)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.cookie)
    })

    fastify.inject({
      method: 'get',
      url: '/methods'
    })
  })

  t.test('Expose jwt methods - 3.x.x conditional jwtDecode', function (t) {
    t.plan(8)

    const fastify = Fastify()
    fastify.register(jwt, {
      secret: 'test',
      cookie: {
        cookieName: 'token',
        signed: false
      },
      jwtDecode: true
    })

    fastify.get('/methods', function (request, reply) {
      t.ok(request.jwtDecode)
      t.ok(request.jwtVerify)
      t.ok(reply.jwtSign)
    })

    fastify.ready(function () {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.options)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.cookie)
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
        private: privateKey,
        public: publicKey
      }
    }).ready(function (error) {
      t.equal(error, undefined)
    })
  })

  t.test('secret as a Buffer', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: Buffer.from('some secret', 'base64')
    }).ready(function (error) {
      t.equal(error, undefined)
    })
  })

  t.test('deprecated use of options prefix', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: {
        private: privateKey,
        public: publicKey
      },
      options: { algorithme: 'RS256' }
    }).ready(function (error) {
      t.equal(error.message, 'options prefix is deprecated')
    })
  })

  t.test('secret as a malformed object', function (t) {
    t.plan(2)

    t.test('only private key (Must return an error)', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey
        },
        sign: {
          algorithm: 'RS256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'missing private key and/or public key')
      })
    })

    t.test('only public key (Must return an error)', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          public: publicKey
        },
        sign: {
          algorithm: 'ES256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'missing private key and/or public key')
      })
    })
  })

  t.test('decode, sign and verify global options (with default HS algorithm)', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: 'test',
      decode: { complete: true },
      sign: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience'
      },
      verify: {
        issuer: 'Some issuer',
        subject: 'Some subject',
        audience: 'Some audience'
      }
    }).ready(function (error) {
      t.equal(error, undefined)
    })
  })

  t.test('decode, sign and verify global options and secret as an object', function (t) {
    t.plan(2)

    t.test('RS algorithm signed certificates', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        decode: { complete: true },
        sign: {
          algorithm: 'RS256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        },
        verify: {
          algorithms: ['RS256'],
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error, undefined)
      })
    })

    t.test('ES algorithm signed certificates', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        decode: { complete: true },
        sign: {
          algorithm: 'ES256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        },
        verify: {
          algorithms: ['ES256'],
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error, undefined)
      })
    })
  })

  t.test('RS/ES algorithm in sign options and secret as string', function (t) {
    t.plan(2)

    t.test('RS algorithm (Must return an error)', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        sign: {
          algorithm: 'RS256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
      })
    })

    t.test('ES algorithm (Must return an error)', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        sign: {
          algorithm: 'ES256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
      })
    })
  })

  t.test('RS/ES algorithm in sign options and secret as a Buffer', function (t) {
    t.plan(2)

    t.test('RS algorithm (Must return an error)', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: Buffer.from('some secret', 'base64'),
        sign: {
          algorithm: 'RS256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
      })
    })

    t.test('ES algorithm (Must return an error)', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, {
        secret: Buffer.from('some secret', 'base64'),
        sign: {
          algorithm: 'ES256',
          audience: 'Some audience',
          issuer: 'Some issuer',
          subject: 'Some subject'
        }
      }).ready(function (error) {
        t.equal(error.message, 'ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
      })
    })
  })

  async function runWithSecret (t, secret) {
    const fastify = Fastify()
    fastify.register(jwt, { secret })

    fastify.post('/sign', async function (request, reply) {
      const token = await reply.jwtSign(request.body)
      return reply.send({ token })
    })

    fastify.get('/verify', function (request, reply) {
      return request.jwtVerify()
    })

    await fastify.ready()

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/verify',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(verifyResponse.payload)
    t.equal(decodedToken.foo, 'bar')
  }

  t.test('secret as a function with callback', t => {
    return runWithSecret(t, function (request, token, callback) {
      callback(null, 'some-secret')
    })
  })

  t.test('secret as a function returning a promise', t => {
    return runWithSecret(t, function (request, token) {
      return Promise.resolve('some-secret')
    })
  })

  t.test('secret as an async function', t => {
    return runWithSecret(t, async function (request, token) {
      return 'some-secret'
    })
  })

  t.test('fail without secret', function (t) {
    t.plan(1)

    const fastify = Fastify()

    fastify
      .register(jwt)
      .ready(function (error) {
        t.equal(error.message, 'missing secret')
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

          t.equal(decoded.foo, 'bar')
        })

        t.test('with callbacks', function (t) {
          t.plan(3)

          fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
            t.error(error)

            fastify.jwt.verify(token, function (error, decoded) {
              t.error(error)
              t.equal(decoded.foo, 'bar')
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
              t.equal(decodedToken.foo, 'bar')
            }).catch(function (error) {
              t.fail(error)
            })
          }).catch(function (error) {
            t.fail(error)
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
              t.equal(decodedToken.foo, 'bar')
            }).catch(function (error) {
              t.fail(error)
            })
          }).catch(function (error) {
            t.fail(error)
          })
        })
      })
  })
})

test('sign and verify with RSA/ECDSA certificates and global options', function (t) {
  t.plan(5)

  t.test('RSA certificates', function (t) {
    t.plan(2)

    t.test('server methods', function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        sign: {
          algorithm: 'RS256',
          issuer: 'test'
        },
        verify: {
          algorithms: ['RS256'],
          issuer: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)

            const token = fastify.jwt.sign({ foo: 'bar' })
            const decoded = fastify.jwt.verify(token)

            t.equal(decoded.foo, 'bar')
            t.equal(decoded.iss, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.equal(decoded.foo, 'bar')
                t.equal(decoded.iss, 'test')
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
        sign: {
          algorithm: 'RS256',
          issuer: 'test'
        },
        verify: {
          issuer: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request, reply) {
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

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.iss, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })

          t.test('with callbacks', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.iss, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })
        })
    })
  })

  t.test('ECDSA certificates', function (t) {
    t.plan(2)

    t.test('server methods', function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        sign: {
          algorithm: 'ES256',
          subject: 'test'
        },
        verify: {
          algorithms: ['ES256'],
          subject: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)

            const token = fastify.jwt.sign({ foo: 'bar' })
            const decoded = fastify.jwt.verify(token)

            t.equal(decoded.foo, 'bar')
            t.equal(decoded.sub, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.equal(decoded.foo, 'bar')
                t.equal(decoded.sub, 'test')
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
          private: privateKeyECDSA,
          public: publicKeyECDSA
        },
        sign: {
          algorithm: 'ES256',
          subject: 'test'
        },
        verify: {
          subject: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request, reply) {
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

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.sub, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })

          t.test('with callbacks', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.sub, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })
        })
    })
  })

  t.test('RSA certificates (passphrase protected)', function (t) {
    t.plan(2)

    t.test('server methods', function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtected, passphrase: 'super secret passphrase' },
          public: publicKeyProtected
        },
        sign: {
          algorithm: 'RS256',
          audience: 'test'
        },
        verify: {
          audience: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)

            const token = fastify.jwt.sign({ foo: 'bar' })
            const decoded = fastify.jwt.verify(token)

            t.equal(decoded.aud, 'test')
            t.equal(decoded.foo, 'bar')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.equal(decoded.aud, 'test')
                t.equal(decoded.foo, 'bar')
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
        sign: {
          algorithm: 'RS256',
          audience: 'test'
        },
        verify: {
          audience: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request, reply) {
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

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.aud, 'test')
                t.equal(decodedToken.foo, 'bar')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })

          t.test('with callbacks', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.aud, 'test')
                t.equal(decodedToken.foo, 'bar')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })
        })
    })
  })

  t.test('ECDSA certificates (passphrase protected)', function (t) {
    t.plan(2)

    t.test('server methods', function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: { key: privateKeyProtectedECDSA, passphrase: 'super secret passphrase' },
          public: publicKeyProtectedECDSA
        },
        sign: {
          algorithm: 'ES256',
          subject: 'test'
        },
        verify: {
          subject: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)

            const token = fastify.jwt.sign({ foo: 'bar' })
            const decoded = fastify.jwt.verify(token)

            t.equal(decoded.foo, 'bar')
            t.equal(decoded.sub, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.equal(decoded.foo, 'bar')
                t.equal(decoded.sub, 'test')
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
          private: { key: privateKeyProtectedECDSA, passphrase: 'super secret passphrase' },
          public: publicKeyProtectedECDSA
        },
        sign: {
          algorithm: 'ES256',
          subject: 'test'
        },
        verify: {
          subject: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request, reply) {
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

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.sub, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })

          t.test('with callbacks', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.sub, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })
        })
    })
  })

  t.test('Overriding global options', function (t) {
    t.plan(2)

    t.test('server methods', function (t) {
      t.plan(2)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: {
          private: privateKey,
          public: publicKey
        },
        sign: {
          algorithm: 'RS256',
          issuer: 'test'
        },
        verify: {
          algorithms: ['RS256'],
          issuer: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)

            const localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.issuer = 'other'

            const token = fastify.jwt.sign({ foo: 'bar' }, localOptions)
            const decoded = fastify.jwt.verify(token, { issuer: 'other' })

            t.equal(decoded.foo, 'bar')
            t.equal(decoded.iss, 'other')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            const localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.issuer = 'other'

            fastify.jwt.sign({ foo: 'bar' }, localOptions, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, { issuer: 'other' }, function (error, decoded) {
                t.error(error)
                t.equal(decoded.foo, 'bar')
                t.equal(decoded.iss, 'other')
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
        sign: {
          algorithm: 'RS256',
          issuer: 'test'
        },
        verify: {
          issuer: 'test'
        }
      })

      fastify.post('/signSync', function (request, reply) {
        reply.jwtSign(request.body)
          .then(function (token) {
            return reply.send({ token })
          })
      })

      fastify.get('/verifySync', function (request, reply) {
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

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.iss, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })

          t.test('with callbacks', function (t) {
            t.plan(3)

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
                t.equal(decodedToken.foo, 'bar')
                t.equal(decodedToken.iss, 'test')
              }).catch(function (error) {
                t.fail(error)
              })
            }).catch(function (error) {
              t.fail(error)
            })
          })
        })
    })
  })
})

test('sign and verify with trusted token', function (t) {
  t.plan(2)
  t.test('Trusted token verification', function (t) {
    t.plan(1)

    const f = Fastify()
    f.register(jwt, { secret: 'test', trusted: (request, { jti }) => jti !== 'untrusted' })
    f.get('/', (request, reply) => {
      request.jwtVerify()
        .then(function (decodedToken) {
          return reply.send(decodedToken)
        })
        .catch(function (error) {
          return reply.send(error)
        })
    })

    const trustedToken = rawJwt.sign({ foo: 'bar' }, 'test', { jwtid: 'trusted' })
    f.inject({
      method: 'get',
      url: '/',
      headers: {
        authorization: `Bearer ${trustedToken}`
      }
    }).then(function (response) {
      t.equal(response.statusCode, 200)
    })
  })

  t.test('Trusted token - async verification', function (t) {
    t.plan(1)

    const f = Fastify()
    f.register(jwt, { secret: 'test', trusted: (request, { jti }) => Promise.resolve(jti !== 'untrusted') })
    f.get('/', (request, reply) => {
      request.jwtVerify()
        .then(function (decodedToken) {
          return reply.send(decodedToken)
        })
        .catch(function (error) {
          return reply.send(error)
        })
    })

    const trustedToken = rawJwt.sign({ foo: 'bar' }, 'test', { jwtid: 'trusted' })
    f.inject({
      method: 'get',
      url: '/',
      headers: {
        authorization: `Bearer ${trustedToken}`
      }
    }).then(function (response) {
      t.equal(response.statusCode, 200)
    })
  })
})

test('decode', function (t) {
  t.plan(2)

  t.test('without global options', function (t) {
    t.plan(2)

    t.test('without local options', function (t) {
      t.plan(1)
      const fastify = Fastify()
      fastify.register(jwt, { secret: 'test' })

      fastify.ready(function () {
        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.decode(token)
        t.equal(decoded.foo, 'bar')
      })
    })

    t.test('with local options', function (t) {
      t.plan(3)

      const fastify = Fastify()
      fastify.register(jwt, { secret: 'test' })

      fastify.ready(function () {
        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.decode(token, { complete: true })

        t.equal(decoded.header.alg, 'HS256')
        t.equal(decoded.header.typ, 'JWT')
        t.equal(decoded.payload.foo, 'bar')
      })
    })
  })

  t.test('with global options', function (t) {
    t.plan(2)

    t.test('without overriding global options', function (t) {
      t.plan(3)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        decode: { complete: true }
      })

      fastify.ready(function () {
        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.decode(token)

        t.equal(decoded.header.alg, 'HS256')
        t.equal(decoded.header.typ, 'JWT')
        t.equal(decoded.payload.foo, 'bar')
      })
    })

    t.test('overriding global options', function (t) {
      t.plan(4)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'test',
        decode: { complete: true }
      })

      fastify.ready(function () {
        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.decode(token, { complete: false })

        t.equal(decoded.header, undefined)
        t.equal(decoded.payload, undefined)
        t.equal(decoded.signature, undefined)
        t.equal(decoded.foo, 'bar')
      })
    })
  })
})

test('errors', function (t) {
  t.plan(10)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', trusted: (request, { jti }) => jti !== 'untrusted' })

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

  fastify.get('/verifyFail', function (request, reply) {
    request.jwtVerify({ issuer: 'foo' })
      .then(function (decodedToken) {
        return reply.send(decodedToken)
      })
      .catch(function (error) {
        return reply.send(error)
      })
  })

  fastify.get('/verifyCallbackCount', function (request, reply) {
    let count = 0
    request.jwtVerify(function () {
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
          t.equal(error.message, 'jwtSign requires a payload')
        })
      })

      t.test('no authorization header error', function (t) {
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify'
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'No Authorization was found in request.headers')
          t.equal(response.statusCode, 401)
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
          t.equal(error.message, 'Format is Authorization: Bearer [token]')
          t.equal(response.statusCode, 400)
        })
      })

      t.test('Bearer authorization format error', function (t) {
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: 'Bearer Bad Format'
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Format is Authorization: Bearer [token]')
          t.equal(response.statusCode, 400)
        })
      })

      t.test('Expired token error', function (t) {
        t.plan(2)

        const expiredToken = fastify.jwt.sign({
          exp: Math.floor(Date.now() / 1000) - 60,
          foo: 'bar'
        })
        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${expiredToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Authorization token expired')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('Invalid signature error', function (t) {
        t.plan(2)

        const invalidSignatureToken = rawJwt.sign({ foo: 'bar' }, Buffer.alloc(64), {})
        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${invalidSignatureToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Authorization token is invalid: invalid signature')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('Untrusted token error', function (t) {
        t.plan(2)

        const untrustedToken = rawJwt.sign({ foo: 'bar' }, 'test', { jwtid: 'untrusted' })
        fastify.inject({
          method: 'get',
          url: '/verifyFailUntrustedToken',
          headers: {
            authorization: `Bearer ${untrustedToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Untrusted authorization token')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('Untrusted token error - async verification', function (t) {
        t.plan(2)

        const f = Fastify()
        f.register(jwt, { secret: 'test', trusted: (request, { jti }) => Promise.resolve(jti !== 'untrusted') })
        f.get('/', (request, reply) => {
          request.jwtVerify()
            .then(function (decodedToken) {
              return reply.send(decodedToken)
            })
            .catch(function (error) {
              return reply.send(error)
            })
        })

        const untrustedToken = rawJwt.sign({ foo: 'bar' }, 'test', { jwtid: 'untrusted' })
        f.inject({
          method: 'get',
          url: '/',
          headers: {
            authorization: `Bearer ${untrustedToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Untrusted authorization token')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('requestVerify function: steed.waterfall error function loop test', function (t) {
        t.plan(3)

        fastify.inject({
          method: 'post',
          url: '/sign',
          payload: {
            payload: { foo: 'bar' }
          }
        }).then(function (signResponse) {
          const token = JSON.parse(signResponse.payload).token
          t.ok(token)

          fastify.inject({
            method: 'get',
            url: '/verifyFail',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (verifyResponse) {
            const error = JSON.parse(verifyResponse.payload)
            t.equal(error.message, 'Authorization token is invalid: jwt issuer invalid. expected: foo')
            t.equal(verifyResponse.statusCode, 401)
          })
        })
      })

      t.test('jwtVerify callback invoked once on error', function (t) {
        t.plan(1)

        fastify.inject({
          method: 'get',
          url: '/verifyCallbackCount',
          headers: {
            authorization: 'Bearer invalid'
          }
        }).then(function (response) {
          const result = JSON.parse(response.payload)
          t.equal(result.count, 1)
        })
      })
    })
})

test('token in a signed cookie, with fastify-cookie parsing', function (t) {
  t.plan(2)

  const fastify = Fastify()
  fastify.register(jwt, {
    secret: 'test',
    cookie: { cookieName: 'jwt', signed: true }
  })
  fastify.register(require('fastify-cookie'), {
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

  fastify.inject({
    method: 'post',
    url: '/sign',
    payload: { foo: 'bar' }
  }).then(async function (signResponse) {
    const cookieName = signResponse.cookies[0].name
    const signedCookie = signResponse.cookies[0].value

    t.equal(cookieName, 'jwt')

    const response = await fastify.inject({
      method: 'get',
      url: '/verify',
      cookies: {
        jwt: signedCookie
      }
    })

    const decodedToken = JSON.parse(response.payload)
    t.equal(decodedToken.foo, 'bar')
  })
})

test('token in cookie, with fastify-cookie parsing', function (t) {
  t.plan(6)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', cookie: { cookieName: 'jwt' } })
  fastify.register(require('fastify-cookie'))

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

  t.test('token present in cookie', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        }
      }).then(function (verifyResponse) {
        const decodedToken = JSON.parse(verifyResponse.payload)
        t.equal(decodedToken.foo, 'bar')
      })
    })
  })

  t.test('token absent in cookie', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'get',
      url: '/verify',
      cookies: {}
    }).then(function (verifyResponse) {
      const error = JSON.parse(verifyResponse.payload)
      t.equal(error.message, 'No Authorization was found in request.cookies')
      t.equal(error.statusCode, 401)
    })
  })

  t.test('both authorization header and cookie present, both valid', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

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
        t.equal(decodedToken.foo, 'bar')
      })
    })
  })

  t.test('both authorization and cookie headers present, cookie token value empty (header fallback)', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

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
        t.equal(decodedToken.foo, 'bar')
      })
    })
  })

  t.test('both authorization and cookie headers present, both values empty', function (t) {
    t.plan(3)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

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
        t.equal(error.message, 'No Authorization was found in request.cookies')
        t.equal(error.statusCode, 401)
      })
    })
  })

  t.test('both authorization and cookie headers present, header malformed', function (t) {
    t.plan(3)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

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
        const error = JSON.parse(verifyResponse.payload)
        t.equal(error.message, 'Format is Authorization: Bearer [token]')
        t.equal(error.statusCode, 400)
      })
    })
  })
})

test('token in cookie, without fastify-cookie parsing', function (t) {
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

  t.test('token present in cookie, but unparsed', function (t) {
    t.plan(3)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        cookies: {
          jwt: token
        }
      }).then(function (verifyResponse) {
        const error = JSON.parse(verifyResponse.payload)
        t.equal(error.message, 'Cookie could not be parsed in request')
        t.equal(error.statusCode, 400)
      })
    })
  })

  t.test('both authorization and cookie headers present, cookie uparsed (header fallback)', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

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
        t.equal(decodedToken.foo, 'bar')
      })
    })
  })
})

test('custom response messages', function (t) {
  t.plan(5)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', messages: { noAuthorizationInHeaderMessage: 'auth header missing', authorizationTokenExpiredMessage: 'token expired', authorizationTokenInvalid: 'invalid token', authorizationTokenUntrusted: 'untrusted token' }, trusted: (request, { jti }) => jti !== 'untrusted' })

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
      t.test('custom no authorization header error', function (t) {
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify'
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'auth header missing')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('fallback authorization header format error', function (t) {
        t.plan(2)

        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: 'Invalid Format'
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Format is Authorization: Bearer [token]')
          t.equal(response.statusCode, 400)
        })
      })

      t.test('custom expired token error', function (t) {
        t.plan(2)

        const expiredToken = fastify.jwt.sign({
          exp: Math.floor(Date.now() / 1000) - 60,
          foo: 'bar'
        })
        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${expiredToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'token expired')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('custom invalid signature error', function (t) {
        t.plan(2)

        const invalidSignatureToken = rawJwt.sign({ foo: 'bar' }, Buffer.alloc(64), {})
        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${invalidSignatureToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'invalid token')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('custom untrusted token error', function (t) {
        t.plan(2)

        const untrustedToken = rawJwt.sign({ foo: 'bar' }, 'test', { jwtid: 'untrusted' })
        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${untrustedToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'untrusted token')
          t.equal(response.statusCode, 401)
        })
      })
    })
})

test('extract custom token', function (t) {
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

  t.test('token can be extracted correctly', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify',
        headers: {
          customauthheader: token
        }
      }).then(function (verifyResponse) {
        t.equal(verifyResponse.statusCode, 200)
      })
    })
  })

  t.test('token can not be extracted', function (t) {
    t.plan(2)
    fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    }).then(function (signResponse) {
      const token = JSON.parse(signResponse.payload).token
      t.ok(token)

      return fastify.inject({
        method: 'get',
        url: '/verify'
      }).then(function (verifyResponse) {
        t.equal(verifyResponse.statusCode, 400)
      })
    })
  })
})

test('format user', function (t) {
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

  t.test('result of jwtVerify is the result of formatUser', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const response = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const user = JSON.parse(response.payload)
    t.equal(user.foo, undefined)
    t.equal(user.baz, 'bar')
  })

  t.test('user is set to the result of formatUser', async function (t) {
    t.plan(3)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const response = await fastify.inject({
      method: 'get',
      url: '/check-user',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const user = JSON.parse(response.payload)
    t.equal(user.foo, undefined)
    t.equal(user.baz, 'bar')
  })
})

test('expose decode token for plugin extension', function (t) {
  t.plan(3)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', jwtDecode: true })

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

  t.test('should decode token without verifying', async function (t) {
    t.plan(2)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.equal(decodedToken.foo, 'bar')
  })

  t.test('should decode token with callback', async function (t) {
    t.plan(2)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token-callback',
      headers: {
        authorization: `Bearer ${token}`
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.equal(decodedToken.foo, 'bar')
  })

  t.test('should handle decode error', async function (t) {
    t.plan(1)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {}
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.equal(decodedToken.statusCode, 401)
  })
})

test('support extended config contract', function (t) {
  t.plan(1)
  const extConfig = {
    sign: {
      issuer: 'api.example.tld'
    },
    verify: {
      issuer: 'api.example.tld',
      extractToken: (req) => (req.headers.otherauth)
    },
    decode: {
      complete: true
    }
  }

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', jwtDecode: true })

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

  t.test('configuration overrides properly passed through callable methods', async function (t) {
    t.plan(7)

    const signResponse = await fastify.inject({
      method: 'post',
      url: '/sign',
      payload: { foo: 'bar' }
    })
    const token = JSON.parse(signResponse.payload).token
    t.ok(token)

    const decodeResponse = await fastify.inject({
      method: 'get',
      url: '/check-decoded-token',
      headers: {
        otherauth: token
      }
    })
    const decodedToken = JSON.parse(decodeResponse.payload)
    t.ok(decodedToken)
    t.equal(decodedToken.header.typ, 'JWT')
    t.equal(decodedToken.payload.iss, extConfig.sign.issuer)
    t.equal(decodedToken.payload.foo, 'bar')

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/check-verify-token',
      headers: {
        otherauth: token
      }
    })
    const decodedAndVerifiedToken = JSON.parse(verifyResponse.payload)
    t.equal(decodedAndVerifiedToken.iss, extConfig.sign.issuer)
    t.equal(decodedAndVerifiedToken.foo, 'bar')
  })
})
