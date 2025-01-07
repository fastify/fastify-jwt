'use strict'

const test = require('tap').test
const Fastify = require('fastify')
const jwt = require('../jwt')

test('Options validation', function (t) {
  t.plan(3)

  t.test('Options are required', function (t) {
    t.plan(1)

    const fastify = Fastify()
    fastify.register(jwt).ready((error) => {
      t.equal(error.message, 'missing secret')
    })
  })

  t.test('Request method aliases', function (t) {
    t.plan(6)

    t.test('jwtDecode fail', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtDecode: true
      }).ready((error) => {
        t.equal(error.message, 'Invalid options.jwtDecode')
      })
    })

    t.test('jwtDecode success', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtDecode: 'hello'
      }).ready((error) => {
        t.error(error)
      })
    })

    t.test('jwtVerify fail', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtVerify: 123
      }).ready((error) => {
        t.equal(error.message, 'Invalid options.jwtVerify')
      })
    })

    t.test('jwtVerify success', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtVerify: String('hello')
      }).ready((error) => {
        t.error(error)
      })
    })

    t.test('jwtSign fail', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtSign: {}
      }).ready((error) => {
        t.equal(error?.message, 'Invalid options.jwtSign')
      })
    })

    t.test('jwtSign success', function (t) {
      t.plan(1)

      const fastify = Fastify()
      fastify.register(jwt, {
        secret: 'sec',
        jwtSign: ''
      }).ready((error) => {
        t.error(error)
      })
    })
  })

  t.test('Secret formats', function (t) {
    t.plan(2)

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
          t.equal(error?.message, 'RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
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
          t.equal(error?.message, 'ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
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
  })
})
