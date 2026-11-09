'use strict'

const fp = require('fastify-plugin')
const { createSigner, createDecoder, createVerifier, TokenError } = require('fast-jwt')
const assert = require('node:assert')
const steed = require('steed')
const { parse } = require('@lukeed/ms')
const createError = require('@fastify/error')

const messages = {
  badRequestErrorMessage: 'Format is Authorization: Bearer [token]',
  badCookieRequestErrorMessage: 'Cookie could not be parsed in request',
  noAuthorizationInHeaderMessage: 'No Authorization was found in request.headers',
  noAuthorizationInCookieMessage: 'No Authorization was found in request.cookies',
  authorizationTokenExpiredMessage: 'Authorization token expired',
  authorizationTokenInvalid: (err) => `Authorization token is invalid: ${err.message}`,
  authorizationTokenUntrusted: 'Untrusted authorization token',
  authorizationTokenUnsigned: 'Unsigned authorization token'
}

const MAX_KEY_CACHE_SIZE = 1000

function getCacheKey (key) {
  if (typeof key === 'string') {
    return key.length > 0 ? `s:${key}` : null
  }
  if (Buffer.isBuffer(key)) {
    return key.length > 0 ? `b:${key.toString('base64')}` : null
  }
  return null
}

function getCachedDynamicFactory (cache, createFn, options) {
  const cacheKey = getCacheKey(options.key)
  if (cacheKey !== null) {
    let cached = cache.get(cacheKey)
    if (!cached) {
      cached = createFn(options)
      if (cache.size >= MAX_KEY_CACHE_SIZE) {
        cache.delete(cache.keys().next().value)
      }
      cache.set(cacheKey, cached)
    }
    return cached
  }
  return createFn(options)
}

function isString (x) {
  return Object.prototype.toString.call(x) === '[object String]'
}

function wrapStaticSecretInCallback (secret) {
  return function (_request, _payload, cb) {
    return cb(null, secret)
  }
}

function wrapSecretCallback (callback) {
  let called = false

  return function (err, result) {
    if (called) return
    called = true
    return callback(err, result)
  }
}

function convertToMs (time, optionName) {
  let milliseconds

  // by default if time is number we assume that they are seconds - see README.md
  if (typeof time === 'number') {
    milliseconds = time * 1000
  } else if (typeof time === 'string' && time.trim() !== '') {
    milliseconds = parse(time)
  }

  if (!Number.isFinite(milliseconds)) {
    throw new TokenError(
      TokenError.codes.invalidOption,
      `The ${optionName} option must be a finite number or a valid string.`
    )
  }

  return milliseconds
}

function convertTemporalProps (options, isVerifyOptions) {
  if (!options) {
    return options
  }

  const formatedOptions = Object.assign({}, options)
  const temporalProps = isVerifyOptions ? ['maxAge'] : ['expiresIn', 'notBefore']

  for (const temporalProp of temporalProps) {
    if (!Object.hasOwn(options, temporalProp)) continue

    if (options[temporalProp] === undefined || options[temporalProp] === null) {
      delete formatedOptions[temporalProp]
    } else {
      formatedOptions[temporalProp] = convertToMs(options[temporalProp], temporalProp)
    }
  }

  return formatedOptions
}

function mergeDefinedOptions (defaultOptions, options) {
  const mergedOptions = Object.assign({}, defaultOptions)

  for (const key of Object.keys(options || {})) {
    if (options[key] !== undefined) {
      mergedOptions[key] = options[key]
    }
  }

  return mergedOptions
}

const nestedOptionKeys = new Set(['decode', 'sign', 'verify'])

function checkForMixedOptions (options, supportedNestedKeys) {
  const hasNestedOptions = supportedNestedKeys.some(key => Object.hasOwn(options, key))

  if (hasNestedOptions && Object.keys(options).some(key => !nestedOptionKeys.has(key))) {
    throw new TokenError(
      TokenError.codes.invalidOption,
      'The options must use either the flat or nested format, not both.'
    )
  }

  return hasNestedOptions
}

function validateOptions (options) {
  assert(options.secret, 'missing secret')
  assert(!options.options, 'options prefix is deprecated')

  assert(!options.jwtVerify || isString(options.jwtVerify), 'Invalid options.jwtVerify')
  assert(!options.jwtDecode || isString(options.jwtDecode), 'Invalid options.jwtDecode')
  assert(!options.jwtSign || isString(options.jwtSign), 'Invalid options.jwtSign')

  if (
    options.sign?.algorithm?.includes('RS') &&
    (typeof options.secret === 'string' ||
      options.secret instanceof Buffer)
  ) {
    throw new Error('RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
  }
  if (
    options.sign?.algorithm?.includes('ES') &&
    (typeof options.secret === 'string' ||
      options.secret instanceof Buffer)
  ) {
    throw new Error('ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret')
  }
}

function fastifyJwt (fastify, options, next) {
  try {
    validateOptions(options)
  } catch (e) {
    return next(e)
  }

  const {
    cookie,
    decode: decodeOptions = {},
    formatUser,
    jwtDecode,
    jwtSign,
    jwtVerify,
    secret,
    sign: initialSignOptions = {},
    trusted,
    decoratorName = 'user',
    // TODO: disable on next major
    // enable errorCacheTTL to prevent breaking change
    verify: initialVerifyOptions = { errorCacheTTL: 600000 },
    ...pluginOptions
  } = options

  const signerCache = new Map()
  const validatorCache = new Map()

  let secretOrPrivateKey
  let secretOrPublicKey

  if (typeof secret === 'object' && !Buffer.isBuffer(secret)) {
    if (!secret.public) {
      return next(new Error('missing public key'))
    }
    secretOrPrivateKey = secret.private
    secretOrPublicKey = secret.public
  } else {
    secretOrPrivateKey = secretOrPublicKey = secret
  }

  let secretCallbackSign = secretOrPrivateKey
  let secretCallbackVerify = secretOrPublicKey
  const isSecretSignStatic = typeof secretCallbackSign !== 'function'
  const isSecretVerifyStatic = typeof secretCallbackVerify !== 'function'
  if (isSecretSignStatic) {
    secretCallbackSign = wrapStaticSecretInCallback(secretCallbackSign)
  }
  if (isSecretVerifyStatic) {
    secretCallbackVerify = wrapStaticSecretInCallback(secretCallbackVerify)
  }

  let signOptions
  let verifyOptions
  try {
    signOptions = convertTemporalProps(initialSignOptions)
    verifyOptions = convertTemporalProps(initialVerifyOptions, true)
  } catch (e) {
    return next(e)
  }
  const hasStaticPrivateKey = isSecretSignStatic && typeof signOptions.key !== 'function'
  const hasStaticPublicKey = isSecretVerifyStatic && typeof verifyOptions.key !== 'function'
  const messagesOptions = Object.assign({}, messages, pluginOptions.messages)
  const namespace = typeof pluginOptions.namespace === 'string' ? pluginOptions.namespace : undefined

  const NoAuthorizationInCookieError = createError('FST_JWT_NO_AUTHORIZATION_IN_COOKIE', messagesOptions.noAuthorizationInCookieMessage, 401)
  const AuthorizationTokenExpiredError = createError('FST_JWT_AUTHORIZATION_TOKEN_EXPIRED', messagesOptions.authorizationTokenExpiredMessage, 401)
  const AuthorizationTokenUntrustedError = createError('FST_JWT_AUTHORIZATION_TOKEN_UNTRUSTED', messagesOptions.authorizationTokenUntrusted, 401)
  const AuthorizationTokenUnsignedError = createError('FAST_JWT_MISSING_SIGNATURE', messagesOptions.authorizationTokenUnsigned, 401)
  const NoAuthorizationInHeaderError = createError('FST_JWT_NO_AUTHORIZATION_IN_HEADER', messagesOptions.noAuthorizationInHeaderMessage, 401)
  const AuthorizationTokenInvalidError = createError('FST_JWT_AUTHORIZATION_TOKEN_INVALID', typeof messagesOptions.authorizationTokenInvalid === 'function'
    ? messagesOptions.authorizationTokenInvalid({ message: '%s' })
    : messagesOptions.authorizationTokenInvalid
  , 401)
  const BadRequestError = createError('FST_JWT_BAD_REQUEST', messagesOptions.badRequestErrorMessage, 400)
  const BadCookieRequestError = createError('FST_JWT_BAD_COOKIE_REQUEST', messagesOptions.badCookieRequestErrorMessage, 400)

  const jwtDecorator = {
    decode,
    options: {
      decode: decodeOptions,
      sign: initialSignOptions,
      verify: initialVerifyOptions,
      messages: messagesOptions,
      decoratorName
    },
    cookie,
    sign,
    verify,
    lookupToken
  }

  let jwtDecodeName = 'jwtDecode'
  let jwtVerifyName = 'jwtVerify'
  let jwtSignName = 'jwtSign'

  if (namespace) {
    if (!fastify.jwt) {
      fastify.decorateRequest(decoratorName, null)
      fastify.decorate('jwt', Object.create(null))
    }

    if (fastify.jwt[namespace]) {
      return next(new Error(`JWT namespace already used "${namespace}"`))
    }
    fastify.jwt[namespace] = jwtDecorator

    jwtDecodeName = jwtDecode || `${namespace}JwtDecode`
    jwtVerifyName = jwtVerify || `${namespace}JwtVerify`
    jwtSignName = jwtSign || `${namespace}JwtSign`
  } else {
    fastify.decorateRequest(decoratorName, null)
    fastify.decorate('jwt', jwtDecorator)
  }

  fastify.decorateRequest(jwtDecodeName, requestDecode)
  fastify.decorateRequest(jwtVerifyName, requestVerify)
  fastify.decorateReply(jwtSignName, replySign)

  let signer
  let decoder
  let verifierConfig
  let verifier
  try {
    const signerConfig = checkAndMergeSignOptions()
    // no signer when configured in verify-mode
    signer = signerConfig.options.key
      ? createSigner(signerConfig.options)
      : null
    decoder = createDecoder(decodeOptions)
    verifierConfig = checkAndMergeVerifyOptions()
    verifier = createVerifier(verifierConfig.options)
  } catch (e) {
    return next(e)
  }

  next()

  function getVerifier (options, globalOptions) {
    const useGlobalOptions = globalOptions ?? options === verifierConfig.options
    // Use global verifier if using global options with static key
    if (useGlobalOptions && hasStaticPublicKey) return verifier
    // Only cache verifier when using default options (except for key)
    if (useGlobalOptions) {
      return getCachedDynamicFactory(validatorCache, createVerifier, options)
    }
    return createVerifier(options)
  }

  function decode (token, options) {
    assert(token, 'missing token')

    let selectedDecoder = decoder

    if (options && options !== decodeOptions && typeof options !== 'function') {
      selectedDecoder = createDecoder(options)
    }

    try {
      return selectedDecoder(token)
    } catch (error) {
      // Ignoring the else branch because it's not possible to test it,
      // it's just a safeguard for future changes in the fast-jwt library
      if (error.code === TokenError.codes.malformed) {
        throw new AuthorizationTokenInvalidError(error.message)
      } else if (error.code === TokenError.codes.invalidType) {
        throw new AuthorizationTokenInvalidError(error.message)
      } /* c8 ignore start */ else {
        throw error
      } /* c8 ignore stop */
    }
  }

  function lookupTokenResolved (request, options) {
    let token
    const extractToken = options.extractToken
    const onlyCookie = options.onlyCookie
    if (extractToken) {
      token = extractToken(request)
      if (!token) {
        throw new BadRequestError()
      }
    } else if (request.headers.authorization && !onlyCookie && /^Bearer\s/i.test(request.headers.authorization)) {
      const parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        token = parts[1]
      } else {
        throw new BadRequestError()
      }
    } else if (cookie) {
      if (request.cookies) {
        if (request.cookies[cookie.cookieName]) {
          const tokenValue = request.cookies[cookie.cookieName]

          if (cookie.signed) {
            const { valid, value } = request.unsignCookie(tokenValue)
            if (!valid) {
              throw new NoAuthorizationInCookieError()
            }
            token = value
          } else {
            token = tokenValue
          }
        } else {
          throw new NoAuthorizationInCookieError()
        }
      } else {
        throw new BadCookieRequestError()
      }
    } else {
      throw new NoAuthorizationInHeaderError()
    }

    return token
  }

  function lookupToken (request, options) {
    assert(request, 'missing request')

    return lookupTokenResolved(request, mergeDefinedOptions(verifyOptions, options))
  }

  function mergeOptionsWithKey (options, useProvidedPrivateKey) {
    if (useProvidedPrivateKey && (typeof useProvidedPrivateKey !== 'boolean')) {
      return Object.assign({}, options, { key: options.key ?? useProvidedPrivateKey })
    } else {
      const key = useProvidedPrivateKey ? secretOrPrivateKey : secretOrPublicKey
      return Object.assign(!options.key ? { key } : {}, options)
    }
  }

  function checkAndMergeOptions (options, defaultOptions, usePrivateKey, callback) {
    if (typeof options === 'function') {
      return { options: mergeOptionsWithKey(defaultOptions, usePrivateKey), callback: options }
    }

    const mergedOptions = mergeDefinedOptions(defaultOptions, options)
    return { options: mergeOptionsWithKey(mergedOptions, usePrivateKey), callback }
  }

  function checkAndMergeSignOptions (options, callback) {
    return checkAndMergeOptions(options, signOptions, true, callback)
  }

  function checkAndMergeVerifyOptions (options, callback) {
    return checkAndMergeOptions(options, verifyOptions, false, callback)
  }

  function sign (payload, options, callback) {
    assert(payload, 'missing payload')
    // if a global signer was not created, sign mode is not supported
    assert(signer, 'unable to sign: secret is configured in verify mode')

    let localSigner = signer

    let localOptions
    try {
      localOptions = typeof options === 'function' ? options : convertTemporalProps(options)
    } catch (error) {
      if (typeof callback === 'function') return callback(error)
      throw error
    }
    const signerConfig = checkAndMergeSignOptions(localOptions, callback)

    if (options && typeof options !== 'function') {
      localSigner = createSigner(signerConfig.options)
    }

    if (typeof signerConfig.callback === 'function') {
      const token = localSigner(payload)
      signerConfig.callback(null, token)
    } else {
      return localSigner(payload)
    }
  }

  function verify (token, options, callback) {
    assert(token, 'missing token')
    assert(secretOrPublicKey, 'missing secret')

    let localVerifier = verifier

    let localOptions
    try {
      localOptions = typeof options === 'function' ? options : convertTemporalProps(options, true)
    } catch (error) {
      if (typeof callback === 'function') return callback(error)
      throw error
    }
    const verifierConfig = checkAndMergeVerifyOptions(localOptions, callback)

    if (options && typeof options !== 'function') {
      localVerifier = getVerifier(verifierConfig.options)
    }

    if (typeof verifierConfig.callback === 'function') {
      const result = localVerifier(token)
      verifierConfig.callback(null, result)
    } else {
      return localVerifier(token)
    }
  }

  function replySign (payload, options, next) {
    // if a global signer was not created, sign mode is not supported
    assert(signer, 'unable to sign: secret is configured in verify mode')

    if (typeof options === 'function') {
      next = options
      options = undefined
    }

    const useGlobalOptions = !options
    const reply = this

    if (useGlobalOptions && hasStaticPrivateKey) {
      if (next === undefined) {
        if (!payload) {
          return Promise.reject(new Error('jwtSign requires a payload'))
        }
        try {
          return Promise.resolve(signer(payload))
        } catch (error) {
          return Promise.reject(error)
        }
      }

      if (!payload) {
        return next(new Error('jwtSign requires a payload'))
      }
      let token
      try {
        token = signer(payload)
      } catch (error) {
        return next(error)
      }
      return next(null, token)
    }

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        reply[jwtSignName](payload, options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    if (!options) {
      options = {}
    }

    try {
      if (checkForMixedOptions(options, ['sign'])) {
        const localSignOptions = convertTemporalProps(options.sign)
        // New supported contract, options supports sign and can expand
        options = {
          sign: mergeDefinedOptions(signOptions, localSignOptions)
        }
      } else {
        const localOptions = convertTemporalProps(options)
        // Original contract, options supports only sign
        options = mergeDefinedOptions(signOptions, localOptions)
      }
    } catch (error) {
      return next(error)
    }

    if (!payload) {
      return next(new Error('jwtSign requires a payload'))
    }

    const resolvedSignOptions = options.sign || options

    if (hasStaticPrivateKey) {
      let token
      try {
        const signerOptions = mergeOptionsWithKey(resolvedSignOptions, true)
        const localSigner = createSigner(signerOptions)
        token = localSigner(payload)
      } catch (error) {
        return next(error)
      }
      return next(null, token)
    }

    steed.waterfall([
      function getSecret (callback) {
        const complete = wrapSecretCallback(callback)
        const signResult = secretCallbackSign(reply.request, payload, complete)

        if (signResult && typeof signResult.then === 'function') {
          signResult.then(result => complete(null, result), complete)
        }
      },
      function signWithSecret (secretOrPrivateKey, callback) {
        let token
        try {
          const signerOptions = mergeOptionsWithKey(resolvedSignOptions, secretOrPrivateKey)
          const localSigner = useGlobalOptions
            ? getCachedDynamicFactory(signerCache, createSigner, signerOptions)
            : createSigner(signerOptions)
          token = localSigner(payload)
        } catch (error) {
          return callback(error)
        }
        if (token && typeof token.then === 'function') {
          token.then(resolvedToken => callback(null, resolvedToken), callback)
        } else {
          callback(null, token)
        }
      }
    ], next)
  }

  function requestDecode (options, next) {
    if (typeof options === 'function' && !next) {
      next = options
      options = {}
    } // support no options

    if (!options) {
      options = {}
    }

    options = {
      decode: mergeDefinedOptions(decodeOptions, options.decode),
      verify: mergeDefinedOptions(verifyOptions, options.verify)
    }

    const request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request[jwtDecodeName](options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    try {
      const token = lookupTokenResolved(request, options.verify)
      const decodedToken = decode(token, options.decode)
      return next(null, decodedToken)
    } catch (err) {
      return next(err)
    }
  }

  function assignUser (request, result) {
    const user = formatUser ? formatUser(result) : result
    request[decoratorName] = user
    return user
  }

  function verifyWithStaticFastPath (request, next) {
    let token
    try {
      token = lookupTokenResolved(request, verifyOptions)
    } catch (err) {
      return next ? next(err) : Promise.reject(err)
    }

    let result
    try {
      result = verifier(token)
    } catch (err) {
      const wrapped = wrapVerifyError(err, true, typeof token !== 'string' && !Buffer.isBuffer(token))
      return next ? next(wrapped) : Promise.reject(wrapped)
    }

    if (!trusted) {
      const user = assignUser(request, result)
      return next ? next(null, user) : Promise.resolve(user)
    }

    let maybePromise
    try {
      maybePromise = trusted(request, result)
    } catch (err) {
      return next ? next(err) : Promise.reject(err)
    }

    if (maybePromise?.then) {
      const settled = maybePromise.then(isTrusted => {
        if (!isTrusted) {
          throw new AuthorizationTokenUntrustedError()
        }
        return assignUser(request, result)
      })
      if (next === undefined) {
        return settled
      }
      settled.then(user => next(null, user), err => next(err))
      return
    }

    if (maybePromise) {
      const user = assignUser(request, result)
      return next ? next(null, user) : Promise.resolve(user)
    }

    const untrustedError = new AuthorizationTokenUntrustedError()
    return next ? next(untrustedError) : Promise.reject(untrustedError)
  }

  function requestVerify (options, next) {
    const request = this

    if (typeof options === 'function') {
      next = options
      options = undefined
    }

    const useGlobalOptions = !options

    if (useGlobalOptions && hasStaticPublicKey && !decodeOptions.checkTyp) {
      return verifyWithStaticFastPath(request, next)
    }

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request[jwtVerifyName](options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    if (!options) {
      options = {}
    }

    try {
      if (checkForMixedOptions(options, ['decode', 'verify'])) {
        const localVerifyOptions = convertTemporalProps(options.verify, true)
        // New supported contract, options supports both decode and verify
        options = {
          decode: mergeDefinedOptions(decodeOptions, options.decode),
          verify: mergeDefinedOptions(verifyOptions, localVerifyOptions)
        }
      } else {
        const localOptions = convertTemporalProps(options, true)
        // Original contract, options supports only verify
        options = mergeDefinedOptions(verifyOptions, localOptions)
      }
    } catch (error) {
      return next(error)
    }

    let token
    let decodedToken
    try {
      token = lookupTokenResolved(request, options.verify || options)
      decodedToken = decode(token, options.decode || decodeOptions)
    } catch (err) {
      return next(err)
    }

    steed.waterfall([
      function getSecret (callback) {
        const complete = wrapSecretCallback(callback)
        const verifyResult = secretCallbackVerify(request, decodedToken, complete)
        if (verifyResult && typeof verifyResult.then === 'function') {
          verifyResult.then(result => complete(null, result), complete)
        }
      },
      function verify (secretOrPublicKey, callback) {
        try {
          const verifierOptions = mergeOptionsWithKey(options.verify || options, secretOrPublicKey)
          const localVerifier = getVerifier(verifierOptions, useGlobalOptions)
          const verifyResult = localVerifier(token)
          if (verifyResult && typeof verifyResult.then === 'function') {
            verifyResult.then(result => callback(null, result), error => wrapError(error, callback))
          } else {
            callback(null, verifyResult)
          }
        } catch (error) {
          return wrapError(error, callback)
        }
      },
      function checkIfIsTrusted (result, callback) {
        if (!trusted) {
          callback(null, result)
        } else {
          const maybePromise = trusted(request, result)

          if (maybePromise?.then) {
            maybePromise
              .then(
                trusted => trusted ? callback(null, result) : callback(new AuthorizationTokenUntrustedError()),
                err => callback(err)
              )
          } else if (maybePromise) {
            callback(null, result)
          } else {
            callback(new AuthorizationTokenUntrustedError())
          }
        }
      }
    ], function (err, result) {
      if (err) {
        next(err)
      } else {
        next(null, assignUser(request, result))
      }
    })
  }

  function wrapVerifyError (error, wrapMalformed, invalidTokenType) {
    if (error.code === TokenError.codes.expired) {
      return new AuthorizationTokenExpiredError()
    }

    if (error.code === TokenError.codes.invalidKey ||
        error.code === TokenError.codes.invalidSignature ||
        error.code === TokenError.codes.invalidClaimValue ||
        error.code === TokenError.codes.missingRequiredClaim ||
        (wrapMalformed && (
          error.code === TokenError.codes.malformed ||
          (error.code === TokenError.codes.invalidType && invalidTokenType)
        ))
    ) {
      return typeof messagesOptions.authorizationTokenInvalid === 'function'
        ? new AuthorizationTokenInvalidError(error.message)
        : new AuthorizationTokenInvalidError()
    }

    if (error.code === TokenError.codes.missingSignature) {
      return new AuthorizationTokenUnsignedError()
    }

    return error
  }

  function wrapError (error, callback) {
    return callback(wrapVerifyError(error, false, false))
  }
}

module.exports = fp(fastifyJwt, {
  fastify: '5.x',
  name: '@fastify/jwt'
})
module.exports.default = fastifyJwt
module.exports.fastifyJwt = fastifyJwt
