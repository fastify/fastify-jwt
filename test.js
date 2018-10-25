'use strict'

const { readFileSync } = require('fs')
const path = require('path')
const test = require('tap').test
const Fastify = require('fastify')

const jwt = require('./jwt')

const privateKey = readFileSync(`${path.join(__dirname, 'certs')}/private.key`, 'utf8')
const publicKey = readFileSync(`${path.join(__dirname, 'certs')}/public.key`, 'utf8')

// passphrase used to protect the private key: super secret passphrase
const privateKeyProtected = readFileSync(`${path.join(__dirname, 'certs')}/private.pem`)
const publicKeyProtected = readFileSync(`${path.join(__dirname, 'certs')}/public.pem`)

const privateKeyECDSA = readFileSync(`${path.join(__dirname, 'certs')}/privateECDSA.key`, 'utf8')
const publicKeyECDSA = readFileSync(`${path.join(__dirname, 'certs')}/publicECDSA.key`, 'utf8')

// passphrase used to protect the private key: super secret passphrase
const privateKeyProtectedECDSA = readFileSync(`${path.join(__dirname, 'certs')}/privateECDSA.pem`)
const publicKeyProtectedECDSA = readFileSync(`${path.join(__dirname, 'certs')}/publicECDSA.pem`)

test('register', function (t) {
  t.plan(9)

  t.test('Expose jwt methods', function (t) {
    t.plan(7)

    const fastify = Fastify()
    fastify.register(jwt, { secret: 'test' })

    fastify.get('/methods', function (request, reply) {
      t.ok(request.jwtVerify)
      t.ok(reply.jwtSign)
    })

    fastify.ready(function () {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.options)
      t.ok(fastify.jwt.secret)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
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
      t.is(error, null)
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
      t.is(error.message, 'options prefix is deprecated')
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
        t.is(error.message, 'missing private key and/or public key')
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
        t.is(error.message, 'missing private key and/or public key')
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
      t.is(error, null)
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
        t.is(error, null)
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
        t.is(error, null)
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
        t.is(error.message, 'RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
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
        t.is(error.message, 'ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
      })
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
      return request.jwtVerify()
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
          }).catch(function (error) {
            t.fail(error)
          })
        }).catch(function (error) {
          t.fail(error)
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
              t.is(decodedToken.foo, 'bar')
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
              t.is(decodedToken.foo, 'bar')
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

            t.is(decoded.foo, 'bar')
            t.is(decoded.iss, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.is(decoded.foo, 'bar')
                t.is(decoded.iss, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.iss, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.iss, 'test')
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

            t.is(decoded.foo, 'bar')
            t.is(decoded.sub, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.is(decoded.foo, 'bar')
                t.is(decoded.sub, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.sub, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.sub, 'test')
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

            t.is(decoded.aud, 'test')
            t.is(decoded.foo, 'bar')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.is(decoded.aud, 'test')
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
                t.is(decodedToken.aud, 'test')
                t.is(decodedToken.foo, 'bar')
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
                t.is(decodedToken.aud, 'test')
                t.is(decodedToken.foo, 'bar')
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

            t.is(decoded.foo, 'bar')
            t.is(decoded.sub, 'test')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            fastify.jwt.sign({ foo: 'bar' }, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, function (error, decoded) {
                t.error(error)
                t.is(decoded.foo, 'bar')
                t.is(decoded.sub, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.sub, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.sub, 'test')
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

            let localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.issuer = 'other'

            const token = fastify.jwt.sign({ foo: 'bar' }, localOptions)
            const decoded = fastify.jwt.verify(token, { issuer: 'other' })

            t.is(decoded.foo, 'bar')
            t.is(decoded.iss, 'other')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            let localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.issuer = 'other'

            fastify.jwt.sign({ foo: 'bar' }, localOptions, function (error, token) {
              t.error(error)

              fastify.jwt.verify(token, { issuer: 'other' }, function (error, decoded) {
                t.error(error)
                t.is(decoded.foo, 'bar')
                t.is(decoded.iss, 'other')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.iss, 'test')
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
                t.is(decodedToken.foo, 'bar')
                t.is(decodedToken.iss, 'test')
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
        t.is(decoded.foo, 'bar')
      })
    })

    t.test('with local options', function (t) {
      t.plan(3)

      const fastify = Fastify()
      fastify.register(jwt, { secret: 'test' })

      fastify.ready(function () {
        const token = fastify.jwt.sign({ foo: 'bar' })
        const decoded = fastify.jwt.decode(token, { complete: true })

        t.is(decoded.header.alg, 'HS256')
        t.is(decoded.header.typ, 'JWT')
        t.is(decoded.payload.foo, 'bar')
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

        t.is(decoded.header.alg, 'HS256')
        t.is(decoded.header.typ, 'JWT')
        t.is(decoded.payload.foo, 'bar')
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

        t.is(decoded.header, undefined)
        t.is(decoded.payload, undefined)
        t.is(decoded.signature, undefined)
        t.is(decoded.foo, 'bar')
      })
    })
  })
})

test('errors', function (t) {
  t.plan(5)

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

  fastify.get('/verifyFail', function (request, reply) {
    request.jwtVerify({ issuer: 'foo' })
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
          t.is(error.message, 'Format is Authorization: Bearer [token]')
          t.is(response.statusCode, 400)
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
            t.is(error.message, 'jwt issuer invalid. expected: foo')
            t.is(verifyResponse.statusCode, 500)
          })
        })
      })
    })
})
