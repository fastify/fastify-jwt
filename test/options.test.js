'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const jwt = require('../jwt')
const { AssertionError } = require('node:assert')

test('Options validation', async function (t) {
  t.plan(3)

  await t.test('Options are required', async function (t) {
    t.plan(1)

    const fastify = Fastify()
    await t.assert.rejects(() => fastify.register(jwt).ready(), new AssertionError({ expected: true, operator: '==', message: 'missing secret' }))
  })

  await t.test('Request method aliases', async function (t) {
    t.plan(6)

    await t.test('jwtDecode fail', async function (t) {
      t.plan(1)

      const fastify = Fastify()
      await t.assert.rejects(() => fastify.register(jwt, {
        secret: 'sec',
        jwtDecode: true
      }).ready(), new AssertionError({ expected: true, operator: '==', message: 'Invalid options.jwtDecode', actual: false }))
    })

    await t.test('jwtDecode success', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: 'sec',
        jwtDecode: 'hello'
      })
    })

    await t.test('jwtVerify fail', async function (t) {
      t.plan(1)

      const fastify = Fastify()

      await t.assert.rejects(() => fastify.register(jwt, {
        secret: 'sec',
        jwtVerify: 123
      }).ready(), new AssertionError({ expected: true, operator: '==', message: 'Invalid options.jwtVerify', actual: false }))
    })

    await t.test('jwtVerify success', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: 'sec',
        jwtVerify: String('hello')
      }).ready()
    })

    await t.test('jwtSign fail', async function (t) {
      t.plan(1)

      const fastify = Fastify()
      await t.assert.rejects(() => fastify.register(jwt, {
        secret: 'sec',
        jwtSign: {}
      }).ready(), new AssertionError({ expected: true, operator: '==', message: 'Invalid options.jwtSign', actual: false }))
    })

    await t.test('jwtSign success', async function (t) {
      const fastify = Fastify()
      await fastify.register(jwt, {
        secret: 'sec',
        jwtSign: ''
      }).ready()
    })
  })

  await t.test('Secret formats', async function (t) {
    t.plan(2)

    await t.test('RS/ES algorithm in sign options and secret as string', async function (t) {
      t.plan(2)

      await t.test('RS algorithm (Must return an error)', async function (t) {
        t.plan(1)

        const fastify = Fastify()
        await t.assert.rejects(() => fastify.register(jwt, {
          secret: 'test',
          sign: {
            algorithm: 'RS256',
            aud: 'Some audience',
            iss: 'Some issuer',
            sub: 'Some subject'
          }
        }).ready(), new Error('RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
      })

      await t.test('ES algorithm (Must return an error)', async function (t) {
        t.plan(1)
        const fastify = Fastify()
        await t.assert.rejects(() => fastify.register(jwt, {
          secret: 'test',
          sign: {
            algorithm: 'ES256',
            aud: 'Some audience',
            iss: 'Some issuer',
            sub: 'Some subject'
          }
        }).ready(), new Error('ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
      })
    })

    await t.test('RS/ES algorithm in sign options and secret as a Buffer', async function (t) {
      t.plan(2)

      await t.test('RS algorithm (Must return an error)', async function (t) {
        t.plan(1)

        const fastify = Fastify()
        await t.assert.rejects(() => fastify.register(jwt, {
          secret: Buffer.from('some secret', 'base64'),
          sign: {
            algorithm: 'RS256',
            aud: 'Some audience',
            iss: 'Some issuer',
            sub: 'Some subject'
          }
        }).ready(), new Error('RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
      })

      await t.test('ES algorithm (Must return an error)', async function (t) {
        t.plan(1)
        const fastify = Fastify()

        await t.assert.rejects(() => fastify.register(jwt, {
          secret: Buffer.from('some secret', 'base64'),
          sign: {
            algorithm: 'ES256',
            aud: 'Some audience',
            iss: 'Some issuer',
            sub: 'Some subject'
          }
        }).ready(), new Error('ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
      })
    })
  })
})
