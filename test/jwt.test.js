'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const { createSigner } = require('fast-jwt')
const jwt = require('../jwt')

const helper = require('./helper')

const passphrase = 'super secret passphrase'
const { privateKey: privateKeyProtected, publicKey: publicKeyProtected } = helper.generateKeyPairProtected(passphrase)
const { privateKey: privateKeyProtectedECDSA, publicKey: publicKeyProtectedECDSA } = helper.generateKeyPairECDSAProtected(passphrase)
const { privateKey, publicKey } = helper.generateKeyPair()
const { privateKey: privateKeyECDSA, publicKey: publicKeyECDSA } = helper.generateKeyPairECDSA()

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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
        iss: 'Some issuer',
        sub: 'Some subject',
        aud: 'Some audience'
      },
      verify: {
        allowedIss: 'Some issuer',
        allowedSub: 'Some subject',
        allowedAud: 'Some audience'
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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
          aud: 'Some audience',
          iss: 'Some issuer',
          sub: 'Some subject'
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
          iss: 'test'
        },
        verify: {
          algorithms: ['RS256'],
          allowedIss: 'test'
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
          sub: 'test'
        },
        verify: {
          algorithms: ['ES256'],
          allowedSub: 'test'
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
          aud: 'test'
        },
        verify: {
          allowedAud: 'test'
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
          sub: 'test'
        },
        verify: {
          allowedSub: 'test'
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
          iss: 'test'
        },
        verify: {
          algorithms: ['RS256'],
          allowedIss: 'test'
        }
      })

      fastify
        .ready()
        .then(function () {
          t.test('synchronous', function (t) {
            t.plan(2)
            const localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.iss = 'other'

            const token = fastify.jwt.sign({ foo: 'bar' }, localOptions)
            const decoded = fastify.jwt.verify(token, { iss: 'other' })

            t.equal(decoded.foo, 'bar')
            t.equal(decoded.iss, 'other')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)
            const localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.iss = 'other'

            fastify.jwt.sign({ foo: 'bar' }, localOptions, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, { iss: 'other' }, function (error, decoded) {
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

    const signer = createSigner({ key: 'test', jti: 'trusted' })
    const trustedToken = signer({ foo: 'bar' })
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

    const signer = createSigner({ key: 'test', jti: 'trusted' })
    const trustedToken = signer({ foo: 'bar' })
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
  t.plan(11)

  const fastify = Fastify()
  fastify.register(jwt, { secret: 'test', trusted: (request, { jti }) => jti !== 'untrusted' })

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

        const signer = createSigner({ key: Buffer.alloc(64) })
        const invalidSignatureToken = signer({ foo: 'bar' })

        fastify.inject({
          method: 'get',
          url: '/verify',
          headers: {
            authorization: `Bearer ${invalidSignatureToken}`
          }
        }).then(function (response) {
          const error = JSON.parse(response.payload)
          t.equal(error.message, 'Authorization token is invalid: The token signature is invalid.')
          t.equal(response.statusCode, 401)
        })
      })

      t.test('Untrusted token error', function (t) {
        t.plan(2)

        const signer = createSigner({ key: 'test', jti: 'untrusted' })
        const untrustedToken = signer({ foo: 'bar' })

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

        const signer = createSigner({ key: 'test', jti: 'untrusted' })
        const untrustedToken = signer({ foo: 'bar' })
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
            url: '/verifyFailOnIss',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (verifyResponse) {
            const error = JSON.parse(verifyResponse.payload)
            t.equal(error.message, 'Authorization token is invalid: The iss claim value is not allowed.')
            t.equal(verifyResponse.statusCode, 401)
          })
        })
      })

      t.test('requestVerify function: algorithm mismatch error', function (t) {
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
            url: '/verifyFailOnAlgorithmMismatch',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (verifyResponse) {
            const error = JSON.parse(verifyResponse.payload)
            t.equal(error.message, 'Authorization token is invalid: Invalid public key provided for algorithms invalid.')
            t.equal(verifyResponse.statusCode, 401)
          })
        })
      })

      t.test('requestVerify function: invalid timestamp', function (t) {
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
            url: '/verifyFailOnInvalidClockTimestamp',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (verifyResponse) {
            const error = JSON.parse(verifyResponse.payload)
            t.equal(error.message, 'The clockTimestamp option must be a positive number.')
            t.equal(verifyResponse.statusCode, 500)
          })
        })
      })

      t.test('jwtVerify callback invoked once on error', function (t) {
        t.plan(2)

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
            url: '/verifyErrorCallbackCount',
            headers: {
              authorization: `Bearer ${token}`
            }
          }).then(function (response) {
            const result = JSON.parse(response.payload)
            t.equal(result.count, 1)
          })
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

  t.test('both authorization and cookie headers present, cookie unparsed (header fallback)', function (t) {
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

        const signer = createSigner({ key: Buffer.alloc(64) })
        const invalidSignatureToken = signer({ foo: 'bar' })

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

        const signer = createSigner({ key: 'test', jti: 'untrusted' })
        const untrustedToken = signer({ foo: 'bar' })
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
    t.equal(decodedToken.payload.iss, extConfig.sign.iss)
    t.equal(decodedToken.payload.foo, 'bar')

    const verifyResponse = await fastify.inject({
      method: 'get',
      url: '/check-verify-token',
      headers: {
        otherauth: token
      }
    })
    const decodedAndVerifiedToken = JSON.parse(verifyResponse.payload)
    t.equal(decodedAndVerifiedToken.iss, extConfig.sign.iss)
    t.equal(decodedAndVerifiedToken.foo, 'bar')
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

  t.test('options are functions', function (t) {
    t.plan(4)
    fastify.jwt.sign({ foo: 'bar' }, (err, token) => {
      t.error(err)
      t.ok(token)

      fastify.jwt.verify(token, (err, result) => {
        t.error(err)
        t.ok(result)
      })
    })
  })

  t.test('no options defined', async function (t) {
    const token = await fastify.jwt.sign({ foo: 'bar' })
    t.ok(token)

    const verifiedToken = await fastify.jwt.verify(token)
    t.ok(verifiedToken)
  })

  t.test('options.sign defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithSignOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.ok(token)
  })

  t.test('general options defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.ok(token)
  })
})

test('supporting time definitions for "maxAge", "expiresIn" and "notBefore"', async function (t) {
  t.plan(3)
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
    },
    jwtDecode: true
  }

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

  t.test('options are functions', function (t) {
    t.plan(6)
    fastify.jwt.sign({ foo: 'bar' }, (err, token) => {
      t.error(err)
      t.ok(token)

      fastify.jwt.verify(token, (err, result) => {
        t.error(err)
        t.ok(result)
        t.ok(result.exp)
        t.equal(typeof result.exp, 'number')
      })
    })
  })

  t.test('options.sign defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithSignOptions',
      payload: { foo: 'bar' }
    })

    const token = JSON.parse(signResponse.payload).token
    t.ok(token)
  })

  t.test('general options defined and merged with signOptions', async function (t) {
    const signResponse = await fastify.inject({
      method: 'post',
      url: '/signWithOptions',
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
    t.ok(decodedToken)
    t.ok(decodedToken.payload.exp)
    t.equal(typeof decodedToken.payload.exp, 'number')
    t.ok(decodedToken.payload.nbf)
    t.equal(typeof decodedToken.payload.nbf, 'number')
  })
})
