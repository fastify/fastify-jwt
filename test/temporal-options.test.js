'use strict'

const { test } = require('node:test')
const Fastify = require('fastify')
const { TokenError } = require('fast-jwt')
const jwt = require('..')

const secret = 'temporal-options-secret'

function expectedTemporalError (optionName) {
  return {
    code: TokenError.codes.invalidOption,
    message: `The ${optionName} option must be a finite number or a valid string.`
  }
}

function assertTemporalError (t, error, optionName) {
  t.assert.ok(error instanceof TokenError)
  t.assert.strictEqual(error.code, expectedTemporalError(optionName).code)
  t.assert.strictEqual(error.message, expectedTemporalError(optionName).message)
}

test('invalid registration temporal options are reported through next', async function (t) {
  const callableSignOptions = function () {}
  callableSignOptions.expiresIn = Infinity
  const callableVerifyOptions = function () {}
  callableVerifyOptions.maxAge = 'not-a-duration'

  const cases = [
    ['expiresIn', 'expiresIn', { sign: { expiresIn: '' } }],
    ['notBefore', 'notBefore', { sign: { notBefore: 'not-a-duration' } }],
    ['maxAge', 'maxAge', { verify: { maxAge: Infinity } }],
    ['callable sign options', 'expiresIn', { sign: callableSignOptions }],
    ['callable verify options', 'maxAge', { verify: callableVerifyOptions }]
  ]

  for (const [name, optionName, options] of cases) {
    await t.test(name, async function (t) {
      const fastify = Fastify()
      let registrationError

      t.assert.doesNotThrow(() => {
        jwt.fastifyJwt(fastify, { secret, ...options }, function (error) {
          registrationError = error
        })
      })
      assertTemporalError(t, registrationError, optionName)
      await fastify.close()
    })
  }
})

test('registration initialization failures are reported through next', async function (t) {
  const fastify = Fastify()
  let registrationError

  t.assert.doesNotThrow(() => {
    jwt.fastifyJwt(fastify, { secret, sign: { algorithm: 'invalid' } }, function (error) {
      registrationError = error
    })
  })
  t.assert.ok(registrationError instanceof TokenError)
  t.assert.strictEqual(registrationError.code, TokenError.codes.invalidOption)
  await fastify.close()
})

test('direct APIs validate temporal options without mutating input', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret }).ready()
  t.after(() => fastify.close())

  const token = fastify.jwt.sign({ value: true })
  const invalidValues = ['', 'not-a-duration', NaN, Infinity, -Infinity, {}, false]

  for (const optionName of ['expiresIn', 'notBefore']) {
    for (const value of invalidValues) {
      const options = { [optionName]: value }
      const originalValue = options[optionName]
      t.assert.throws(
        () => fastify.jwt.sign({ value: true }, options),
        error => {
          assertTemporalError(t, error, optionName)
          return true
        }
      )
      t.assert.strictEqual(options[optionName], originalValue)
    }
  }

  for (const value of invalidValues) {
    const options = { maxAge: value }
    const originalValue = options.maxAge
    t.assert.throws(
      () => fastify.jwt.verify(token, options),
      error => {
        assertTemporalError(t, error, 'maxAge')
        return true
      }
    )
    t.assert.strictEqual(options.maxAge, originalValue)
  }
})

test('direct API callbacks receive temporal conversion errors', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret }).ready()
  t.after(() => fastify.close())

  let signCallbackCalls = 0
  t.assert.doesNotThrow(() => {
    fastify.jwt.sign({ value: true }, { expiresIn: '' }, function (error, token) {
      signCallbackCalls++
      assertTemporalError(t, error, 'expiresIn')
      t.assert.strictEqual(token, undefined)
    })
  })
  t.assert.strictEqual(signCallbackCalls, 1)

  const token = fastify.jwt.sign({ value: true })
  let verifyCallbackCalls = 0
  t.assert.doesNotThrow(() => {
    fastify.jwt.verify(token, { maxAge: Infinity }, function (error, result) {
      verifyCallbackCalls++
      assertTemporalError(t, error, 'maxAge')
      t.assert.strictEqual(result, undefined)
    })
  })
  t.assert.strictEqual(verifyCallbackCalls, 1)

  let callbackToken
  fastify.jwt.sign({ value: true }, function (error, result) {
    t.assert.ifError(error)
    callbackToken = result
  })
  fastify.jwt.verify(callbackToken, function (error, result) {
    t.assert.ifError(error)
    t.assert.strictEqual(result.value, true)
  })
})

test('registration and direct APIs accept zero and convert finite numbers from seconds to milliseconds', async function (t) {
  const configuredFastify = Fastify()
  await configuredFastify.register(jwt, {
    secret,
    sign: { expiresIn: 0, notBefore: 0 },
    verify: { maxAge: 0 }
  }).ready()
  await configuredFastify.close()

  const fastify = Fastify()
  await fastify.register(jwt, { secret }).ready()
  t.after(() => fastify.close())

  t.assert.doesNotThrow(() => fastify.jwt.sign({ value: true }, { expiresIn: 0 }))
  t.assert.doesNotThrow(() => fastify.jwt.sign({ value: true }, { notBefore: 0 }))

  const expToken = fastify.jwt.sign({ value: true }, { expiresIn: 2 })
  const expPayload = fastify.jwt.decode(expToken)
  t.assert.strictEqual(expPayload.exp - expPayload.iat, 2)

  const nbfToken = fastify.jwt.sign({ value: true }, { notBefore: 2 })
  const nbfPayload = fastify.jwt.decode(nbfToken)
  t.assert.strictEqual(nbfPayload.nbf - nbfPayload.iat, 2)

  const token = fastify.jwt.sign({ value: true })
  t.assert.throws(
    () => fastify.jwt.verify(token, { maxAge: 0 }),
    error => error.code === TokenError.codes.expired
  )
})

test('direct APIs only process own temporal option properties', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret }).ready()
  t.after(() => fastify.close())

  const signOptions = Object.create({ expiresIn: '', notBefore: 'not-a-duration' })
  const token = fastify.jwt.sign({ value: true }, signOptions)
  t.assert.ok(token)

  const verifyOptions = Object.create({ maxAge: Infinity })
  t.assert.deepStrictEqual(fastify.jwt.verify(token, verifyOptions).value, true)
})

test('reply decorator validates legacy and nested temporal options', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  const callableSignOptions = function () {}
  callableSignOptions.expiresIn = Infinity
  const routeOptions = {
    legacyExpiresIn: { expiresIn: '' },
    nestedExpiresIn: { sign: { expiresIn: 'not-a-duration' } },
    legacyNotBefore: { notBefore: Infinity },
    nestedNotBefore: { sign: { notBefore: {} } },
    nestedCallable: { sign: callableSignOptions }
  }

  for (const [name, options] of Object.entries(routeOptions)) {
    fastify.get(`/${name}`, function (_request, reply) {
      return reply.jwtSign({ value: true }, options)
    })
  }

  fastify.get('/legacyZero', function (_request, reply) {
    return reply.jwtSign({ value: true }, { expiresIn: 0, notBefore: 0 })
  })
  fastify.get('/nestedZero', function (_request, reply) {
    return reply.jwtSign({ value: true }, { sign: { expiresIn: 0, notBefore: 0 } })
  })

  await fastify.ready()
  t.after(() => fastify.close())

  for (const [name, optionName] of [
    ['legacyExpiresIn', 'expiresIn'],
    ['nestedExpiresIn', 'expiresIn'],
    ['legacyNotBefore', 'notBefore'],
    ['nestedNotBefore', 'notBefore'],
    ['nestedCallable', 'expiresIn']
  ]) {
    const response = await fastify.inject(`/${name}`)
    t.assert.strictEqual(response.statusCode, 500)
    t.assert.strictEqual(response.json().code, TokenError.codes.invalidOption)
    t.assert.strictEqual(response.json().message, expectedTemporalError(optionName).message)
  }

  t.assert.strictEqual((await fastify.inject('/legacyZero')).statusCode, 200)
  t.assert.strictEqual((await fastify.inject('/nestedZero')).statusCode, 200)
  t.assert.deepStrictEqual(routeOptions, {
    legacyExpiresIn: { expiresIn: '' },
    nestedExpiresIn: { sign: { expiresIn: 'not-a-duration' } },
    legacyNotBefore: { notBefore: Infinity },
    nestedNotBefore: { sign: { notBefore: {} } },
    nestedCallable: { sign: callableSignOptions }
  })
  t.assert.strictEqual(callableSignOptions.expiresIn, Infinity)
})

test('request decorator validates legacy and nested maxAge options', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  const legacyOptions = { maxAge: '' }
  const nestedOptions = { verify: { maxAge: NaN } }
  const callableVerifyOptions = function () {}
  callableVerifyOptions.maxAge = Infinity

  fastify.get('/legacyInvalid', function (request) {
    return request.jwtVerify(legacyOptions)
  })
  fastify.get('/nestedInvalid', function (request) {
    return request.jwtVerify(nestedOptions)
  })
  fastify.get('/nestedCallable', function (request) {
    return request.jwtVerify({ verify: callableVerifyOptions })
  })
  fastify.get('/legacyZero', function (request) {
    return request.jwtVerify({ maxAge: 0 })
  })
  fastify.get('/nestedZero', function (request) {
    return request.jwtVerify({ verify: { maxAge: 0 } })
  })

  await fastify.ready()
  t.after(() => fastify.close())

  const token = fastify.jwt.sign({ value: true })
  const authorization = { authorization: `Bearer ${token}` }

  for (const [url, optionName] of [
    ['/legacyInvalid', 'maxAge'],
    ['/nestedInvalid', 'maxAge'],
    ['/nestedCallable', 'maxAge']
  ]) {
    const response = await fastify.inject({ url, headers: authorization })
    t.assert.strictEqual(response.statusCode, 500)
    t.assert.strictEqual(response.json().code, TokenError.codes.invalidOption)
    t.assert.strictEqual(response.json().message, expectedTemporalError(optionName).message)
  }

  for (const url of ['/legacyZero', '/nestedZero']) {
    const response = await fastify.inject({ url, headers: authorization })
    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(response.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_EXPIRED')
  }
  t.assert.deepStrictEqual(legacyOptions, { maxAge: '' })
  t.assert.deepStrictEqual(nestedOptions, { verify: { maxAge: NaN } })
  t.assert.strictEqual(callableVerifyOptions.maxAge, Infinity)
})

test('decorator callbacks receive legacy and nested temporal conversion errors', async function (t) {
  const fastify = Fastify()
  await fastify.register(jwt, { secret })

  fastify.get('/replyLegacyCallback', function (_request, reply) {
    return new Promise(resolve => {
      reply.jwtSign({ value: true }, { expiresIn: '' }, function (error, token) {
        resolve({ code: error.code, message: error.message, token })
      })
    })
  })
  fastify.get('/replyNestedCallback', function (_request, reply) {
    return new Promise(resolve => {
      reply.jwtSign({ value: true }, { sign: { notBefore: Infinity } }, function (error, token) {
        resolve({ code: error.code, message: error.message, token })
      })
    })
  })
  fastify.get('/requestLegacyCallback', function (request) {
    return new Promise(resolve => {
      request.jwtVerify({ maxAge: '' }, function (error, result) {
        resolve({ code: error.code, message: error.message, result })
      })
    })
  })
  fastify.get('/requestNestedCallback', function (request) {
    return new Promise(resolve => {
      request.jwtVerify({ verify: { maxAge: Infinity } }, function (error, result) {
        resolve({ code: error.code, message: error.message, result })
      })
    })
  })

  await fastify.ready()
  t.after(() => fastify.close())

  for (const [url, optionName] of [
    ['/replyLegacyCallback', 'expiresIn'],
    ['/replyNestedCallback', 'notBefore']
  ]) {
    const response = await fastify.inject(url)
    t.assert.strictEqual(response.statusCode, 200)
    t.assert.strictEqual(response.json().code, TokenError.codes.invalidOption)
    t.assert.strictEqual(response.json().message, expectedTemporalError(optionName).message)
    t.assert.strictEqual(response.json().token, undefined)
  }

  const token = fastify.jwt.sign({ value: true })
  const authorization = { authorization: `Bearer ${token}` }
  for (const url of ['/requestLegacyCallback', '/requestNestedCallback']) {
    const response = await fastify.inject({ url, headers: authorization })
    t.assert.strictEqual(response.statusCode, 200)
    t.assert.strictEqual(response.json().code, TokenError.codes.invalidOption)
    t.assert.strictEqual(response.json().message, expectedTemporalError('maxAge').message)
    t.assert.strictEqual(response.json().result, undefined)
  }
})

test('reply decorator preserves global defaults for nullish local temporal options', async function (t) {
  const globalOptions = {
    secret,
    sign: {
      expiresIn: '1 hour',
      notBefore: '2 minutes'
    }
  }
  const fastify = Fastify()
  await fastify.register(jwt, globalOptions)

  const legacyOptions = { expiresIn: undefined, notBefore: null }
  const nestedOptions = { sign: { expiresIn: null, notBefore: undefined } }

  fastify.get('/legacy', function (_request, reply) {
    return reply.jwtSign({ value: true }, legacyOptions)
  })
  fastify.get('/nested', function (_request, reply) {
    return reply.jwtSign({ value: true }, nestedOptions)
  })

  await fastify.ready()
  t.after(() => fastify.close())

  for (const url of ['/legacy', '/nested']) {
    const response = await fastify.inject(url)
    const payload = fastify.jwt.decode(response.payload)
    t.assert.strictEqual(payload.exp - payload.iat, 60 * 60)
    t.assert.strictEqual(payload.nbf - payload.iat, 2 * 60)
  }

  t.assert.deepStrictEqual(legacyOptions, { expiresIn: undefined, notBefore: null })
  t.assert.deepStrictEqual(nestedOptions, { sign: { expiresIn: null, notBefore: undefined } })
  t.assert.strictEqual(globalOptions.sign.expiresIn, '1 hour')
  t.assert.strictEqual(globalOptions.sign.notBefore, '2 minutes')
})

test('request decorator preserves global maxAge for nullish legacy and nested options', async function (t) {
  const globalOptions = { secret, verify: { maxAge: 1 } }
  const fastify = Fastify()
  await fastify.register(jwt, globalOptions)

  const legacyOptions = { maxAge: undefined }
  const nestedOptions = { verify: { maxAge: null } }

  fastify.get('/legacy', function (request) {
    return request.jwtVerify(legacyOptions)
  })
  fastify.get('/nested', function (request) {
    return request.jwtVerify(nestedOptions)
  })

  await fastify.ready()
  t.after(() => fastify.close())

  const token = fastify.jwt.sign({ value: true, iat: Math.floor(Date.now() / 1000) - 10 })
  const authorization = { authorization: `Bearer ${token}` }

  for (const url of ['/legacy', '/nested']) {
    const response = await fastify.inject({ url, headers: authorization })
    t.assert.strictEqual(response.statusCode, 401)
    t.assert.strictEqual(response.json().code, 'FST_JWT_AUTHORIZATION_TOKEN_EXPIRED')
  }

  t.assert.deepStrictEqual(legacyOptions, { maxAge: undefined })
  t.assert.deepStrictEqual(nestedOptions, { verify: { maxAge: null } })
  t.assert.strictEqual(globalOptions.verify.maxAge, 1)
})
