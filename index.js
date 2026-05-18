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

function isString (x) {
  return Object.prototype.toString.call(x) === '[object String]'
}

function resolveSecret (secretValue, context, callback) {
  if (typeof secretValue !== 'function') {
    return callback(null, secretValue)
  }

  let called = false
  function once (err, val) {
    if (called) return
    called = true
    callback(err, val)
  }

  const result = secretValue(context, once)

  if (result && typeof result.then === 'function') {
    result.then(secret => once(null, secret), once)
  }
}

function convertToMs (time) {
  // by default if time is number we assume that they are seconds - see README.md
  if (typeof time === 'number') {
    return time * 1000
  }
  return parse(time)
}

function convertTemporalProps (options, isVerifyOptions) {
  if (!options || typeof options === 'function') {
    return options
  }

  const formatedOptions = Object.assign({}, options)

  if (isVerifyOptions && formatedOptions.maxAge) {
    formatedOptions.maxAge = convertToMs(formatedOptions.maxAge)
  } else if (formatedOptions.expiresIn || formatedOptions.notBefore) {
    if (formatedOptions.expiresIn) {
      formatedOptions.expiresIn = convertToMs(formatedOptions.expiresIn)
    }

    if (formatedOptions.notBefore) {
      formatedOptions.notBefore = convertToMs(formatedOptions.notBefore)
    }
  }

  return formatedOptions
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

  const signOptions = convertTemporalProps(initialSignOptions)
  const verifyOptions = convertTemporalProps(initialVerifyOptions, true)
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

  const signerConfig = checkAndMergeSignOptions()
  // no signer when configured in verify-mode or when secret is a function (resolved per-call)
  const signer = (signerConfig.options.key && typeof signerConfig.options.key !== 'function')
    ? createSigner(signerConfig.options)
    : null
  const decoder = createDecoder(decodeOptions)
  const completeDecoder = createDecoder(Object.assign({}, decodeOptions, { complete: true }))
  const verifierConfig = checkAndMergeVerifyOptions()
  // no global verifier when secret is a function (resolved per-call)
  const verifier = (verifierConfig.options.key && typeof verifierConfig.options.key !== 'function')
    ? createVerifier(verifierConfig.options)
    : null

  next()

  function getVerifier (options, globalOptions) {
    const useGlobalOptions = globalOptions ?? options === verifierConfig.options
    // Use global verifier if using global options with static key
    if (useGlobalOptions && verifier) return verifier
    // Only cache verifier when using default options (except for key)
    if (useGlobalOptions && options.key && typeof options.key === 'string') {
      let verifier = validatorCache.get(options.key)
      if (!verifier) {
        verifier = createVerifier(options)
        validatorCache.set(options.key, verifier)
      }
      return verifier
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

  function lookupToken (request, options) {
    assert(request, 'missing request')

    options = Object.assign({}, verifyOptions, options)

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

          token = cookie.signed ? request.unsignCookie(tokenValue).value : tokenValue
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

  function withStaticKey (options, usePrivateKey) {
    if (options.key) return Object.assign({}, options)
    const key = usePrivateKey ? secretOrPrivateKey : secretOrPublicKey
    if (!key) return Object.assign({}, options)
    return Object.assign({}, options, { key })
  }

  function withResolvedKey (options, key) {
    return Object.assign({}, options, { key })
  }

  function checkAndMergeOptions (options, defaultOptions, usePrivateKey, callback) {
    if (typeof options === 'function') {
      return { options: withStaticKey(defaultOptions, usePrivateKey), callback: options }
    }

    return { options: withStaticKey(options || defaultOptions, usePrivateKey), callback }
  }

  function checkAndMergeSignOptions (options, callback) {
    return checkAndMergeOptions(options, signOptions, true, callback)
  }

  function checkAndMergeVerifyOptions (options, callback) {
    return checkAndMergeOptions(options, verifyOptions, false, callback)
  }

  function sign (payload, options, callback) {
    assert(payload, 'missing payload')
    assert(secretOrPrivateKey, 'unable to sign: secret is configured in verify mode')

    const localOptions = convertTemporalProps(options)
    const signerConfig = checkAndMergeSignOptions(localOptions, callback)

    if (typeof signerConfig.callback !== 'function') {
      assert(typeof signerConfig.options.key !== 'function', 'callback is required when secret is a function')
      let localSigner = signer
      if (options && typeof options !== 'function') {
        localSigner = createSigner(signerConfig.options)
      }
      return localSigner(payload)
    }

    const cb = signerConfig.callback

    // Fast-path: reuse global signer when no custom options were passed
    if (signer && (!options || typeof options === 'function')) {
      try {
        cb(null, signer(payload))
      /* c8 ignore next 3 */
      } catch (error) {
        cb(error)
      }
      return
    }

    const context = { operation: 'sign', payload }
    resolveSecret(signerConfig.options.key, context, function (err, secret) {
      if (err) return cb(err)
      try {
        const resolvedOptions = withResolvedKey(signerConfig.options, secret)
        const localSigner = createSigner(resolvedOptions)
        cb(null, localSigner(payload))
      /* c8 ignore next 3 */
      } catch (error) {
        cb(error)
      }
    })
  }

  function verify (token, options, callback) {
    assert(token, 'missing token')
    assert(secretOrPublicKey, 'missing secret')

    const localOptions = convertTemporalProps(options, true)
    const verifierConfig = checkAndMergeVerifyOptions(localOptions, callback)

    if (typeof verifierConfig.callback !== 'function') {
      assert(typeof verifierConfig.options.key !== 'function', 'callback is required when secret is a function')
      let localVerifier = verifier
      if (options && typeof options !== 'function') {
        localVerifier = getVerifier(verifierConfig.options)
      }
      return localVerifier(token)
    }

    const cb = verifierConfig.callback

    // Fast-path: reuse global verifier when no custom options were passed
    if (verifier && (!options || typeof options === 'function')) {
      try {
        cb(null, verifier(token))
      } catch (error) {
        cb(error)
      }
      return
    }

    const decoded = completeDecoder(token)
    const context = { operation: 'verify', header: decoded.header, payload: decoded.payload, signature: decoded.signature }
    resolveSecret(verifierConfig.options.key, context, function (err, secret) {
      if (err) return cb(err)
      try {
        const resolvedOptions = withResolvedKey(verifierConfig.options, secret)
        const localVerifier = getVerifier(resolvedOptions)
        cb(null, localVerifier(token))
      } catch (error) {
        cb(error)
      }
    })
  }

  function replySign (payload, options, next) {
    // sign mode is not supported when only a public key is provided
    assert(secretOrPrivateKey, 'unable to sign: secret is configured in verify mode')

    let useLocalSigner = true
    if (typeof options === 'function') {
      next = options
      options = {}
      useLocalSigner = false
    } // support no options

    if (!options) {
      options = {}
      useLocalSigner = false
    }

    const reply = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        reply[jwtSignName](payload, options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    if (options.sign) {
      const localSignOptions = convertTemporalProps(options.sign)
      // New supported contract, options supports sign and can expand
      options = {
        sign: withStaticKey(Object.assign({}, signOptions, localSignOptions), true)
      }
    } else {
      const localOptions = convertTemporalProps(options)
      // Original contract, options supports only sign
      options = withStaticKey(Object.assign({}, signOptions, localOptions), true)
    }

    if (!payload) {
      return next(new Error('jwtSign requires a payload'))
    }

    const replySignOptions = options.sign || options

    steed.waterfall([
      function getSecret (callback) {
        const context = { operation: 'sign', payload, request: reply.request }
        resolveSecret(replySignOptions.key, context, callback)
      },
      function sign (secretOrPrivateKey, callback) {
        if (useLocalSigner) {
          const signerOptions = withResolvedKey(replySignOptions, secretOrPrivateKey)
          const localSigner = createSigner(signerOptions)
          const token = localSigner(payload)
          callback(null, token)
        } else {
          const signerOptions = withResolvedKey(signerConfig.options, secretOrPrivateKey)
          const localSigner = signer || createSigner(signerOptions)
          const token = localSigner(payload)
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
      decode: Object.assign({}, decodeOptions, options.decode),
      verify: Object.assign({}, verifyOptions, options.verify)
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
      const token = lookupToken(request, options.verify)
      const decodedToken = decode(token, options.decode)
      return next(null, decodedToken)
    } catch (err) {
      return next(err)
    }
  }

  function requestVerify (options, next) {
    const request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request[jwtVerifyName](options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    const useGlobalOptions = !options

    if (typeof options === 'function') {
      next = options
      options = {}
    } // support no options

    if (!options) {
      options = {}
    }

    if (options.decode || options.verify) {
      const localVerifyOptions = convertTemporalProps(options.verify, true)
      // New supported contract, options supports both decode and verify
      options = {
        decode: Object.assign({}, decodeOptions, options.decode),
        verify: withStaticKey(Object.assign({}, verifyOptions, localVerifyOptions), false)
      }
    } else {
      const localOptions = convertTemporalProps(options, true)
      // Original contract, options supports only verify
      options = withStaticKey(Object.assign({}, verifyOptions, localOptions), false)
    }

    let token
    try {
      token = lookupToken(request, options.verify || options)
    } catch (err) {
      return next(err)
    }

    let completeDecode
    try {
      completeDecode = completeDecoder(token)
    } catch (error) {
      // Ignoring the else branch because it's not possible to test it,
      // it's just a safeguard for future changes in the fast-jwt library
      if (error.code === TokenError.codes.malformed) {
        return next(new AuthorizationTokenInvalidError(error.message))
      } else if (error.code === TokenError.codes.invalidType) {
        return next(new AuthorizationTokenInvalidError(error.message))
      } /* c8 ignore start */ else {
        return next(error)
      } /* c8 ignore stop */
    }

    const requestVerifyOptions = options.verify || options

    steed.waterfall([
      function getSecret (callback) {
        const context = {
          operation: 'verify',
          header: completeDecode.header,
          payload: completeDecode.payload,
          signature: completeDecode.signature,
          request
        }
        resolveSecret(requestVerifyOptions.key, context, callback)
      },
      function verify (secretOrPublicKey, callback) {
        try {
          const verifierOptions = secretOrPublicKey
            ? withResolvedKey(requestVerifyOptions, secretOrPublicKey)
            /* c8 ignore next */
            : Object.assign({}, requestVerifyOptions)
          const localVerifier = getVerifier(verifierOptions, useGlobalOptions)
          const verifyResult = localVerifier(token)
          /* c8 ignore next 2 */
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
              .then(trusted => trusted ? callback(null, result) : callback(new AuthorizationTokenUntrustedError()))
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
        const user = formatUser ? formatUser(result) : result
        request[decoratorName] = user
        next(null, user)
      }
    })
  }

  function wrapError (error, callback) {
    if (error.code === TokenError.codes.expired) {
      return callback(new AuthorizationTokenExpiredError())
    }

    if (error.code === TokenError.codes.invalidKey ||
        error.code === TokenError.codes.invalidSignature ||
        error.code === TokenError.codes.invalidClaimValue ||
        error.code === TokenError.codes.missingRequiredClaim
    ) {
      return callback(typeof messagesOptions.authorizationTokenInvalid === 'function'
        ? new AuthorizationTokenInvalidError(error.message)
        : new AuthorizationTokenInvalidError())
    }

    if (error.code === TokenError.codes.missingSignature) {
      return callback(new AuthorizationTokenUnsignedError())
    }

    return callback(error)
  }
}

module.exports = fp(fastifyJwt, {
  fastify: '5.x',
  name: '@fastify/jwt'
})
module.exports.default = fastifyJwt
module.exports.fastifyJwt = fastifyJwt
