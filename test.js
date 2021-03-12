'use strict'

const { readFileSync } = require('fs')
const path = require('path')
const test = require('tap').test
const Fastify = require('fastify')
const rawJwt = require('jsonwebtoken')

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
  t.plan(12)

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

  t.test('secret as a promise', { only: true }, function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: function () {
        return new Promise((resolve, reject) => {
          resolve('supersecret')
        })
      }
    }).ready(function (error) {
      t.is(error, undefined)
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
      t.is(error, undefined)
    })
  })

  t.test('secret as a Buffer', function (t) {
    t.plan(1)
    const fastify = Fastify()
    fastify.register(jwt, {
      secret: Buffer.from('some secret', 'base64')
    }).ready(function (error) {
      t.is(error, undefined)
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
      t.is(error, undefined)
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
        t.is(error, undefined)
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
        t.is(error, undefined)
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
        t.is(error.message, 'RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
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

            const localOptions = Object.assign({}, fastify.jwt.options.sign)
            localOptions.issuer = 'other'

            const token = fastify.jwt.sign({ foo: 'bar' }, localOptions)
            const decoded = fastify.jwt.verify(token, { issuer: 'other' })

            t.is(decoded.foo, 'bar')
            t.is(decoded.iss, 'other')
          })

          t.test('with callbacks', function (t) {
            t.plan(4)

            const localOptions = Object.assign({}, fastify.jwt.options.sign)
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
      t.is(response.statusCode, 200)
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
      t.is(response.statusCode, 200)
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
          t.is(error.message, 'Authorization token expired')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'Authorization token is invalid: invalid signature')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'Untrusted authorization token')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'Untrusted authorization token')
          t.is(response.statusCode, 401)
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
            t.is(error.message, 'Authorization token is invalid: jwt issuer invalid. expected: foo')
            t.is(verifyResponse.statusCode, 401)
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
          t.is(result.count, 1)
        })
      })
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
        t.is(decodedToken.foo, 'bar')
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
      t.is(error.message, 'No Authorization was found in request.cookies')
      t.is(error.statusCode, 401)
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
        t.is(decodedToken.foo, 'bar')
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
        t.is(decodedToken.foo, 'bar')
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
        t.is(error.message, 'No Authorization was found in request.cookies')
        t.is(error.statusCode, 401)
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
        t.is(error.message, 'Format is Authorization: Bearer [token]')
        t.is(error.statusCode, 400)
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
        t.is(error.message, 'Cookie could not be parsed in request')
        t.is(error.statusCode, 400)
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
        t.is(decodedToken.foo, 'bar')
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
          t.is(error.message, 'auth header missing')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'Format is Authorization: Bearer [token]')
          t.is(response.statusCode, 400)
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
          t.is(error.message, 'token expired')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'invalid token')
          t.is(response.statusCode, 401)
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
          t.is(error.message, 'untrusted token')
          t.is(response.statusCode, 401)
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
        t.is(verifyResponse.statusCode, 200)
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
        t.is(verifyResponse.statusCode, 400)
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
    t.is(user.foo, undefined)
    t.is(user.baz, 'bar')
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
    t.is(user.foo, undefined)
    t.is(user.baz, 'bar')
  })
})
