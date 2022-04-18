'use strict'

const fp = require('fastify-plugin')
const { createSigner, createDecoder, createVerifier, TokenError } = require('fast-jwt')
const assert = require('assert')
const steed = require('steed')
const { parse } = require('@lukeed/ms')
const {
  BadRequest,
  Unauthorized
} = require('http-errors')

const messages = {
  badRequestErrorMessage: 'Format is Authorization: Bearer [token]',
  badCookieRequestErrorMessage: 'Cookie could not be parsed in request',
  noAuthorizationInHeaderMessage: 'No Authorization was found in request.headers',
  noAuthorizationInCookieMessage: 'No Authorization was found in request.cookies',
  authorizationTokenExpiredMessage: 'Authorization token expired',
  authorizationTokenInvalid: (err) => `Authorization token is invalid: ${err.message}`,
  authorizationTokenUntrusted: 'Untrusted authorization token'
}

function wrapStaticSecretInCallback (secret) {
  return function (request, payload, cb) {
    return cb(null, secret)
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

function fastifyJwt (fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  if (options.options) {
    return next(new Error('options prefix is deprecated'))
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
    verify: initialVerifyOptions = {},
    ...pluginOptions
  } = options

  let secretOrPrivateKey
  let secretOrPublicKey

  if (typeof secret === 'object' && !Buffer.isBuffer(secret)) {
    if (!secret.private || !secret.public) {
      return next(new Error('missing private key and/or public key'))
    }
    secretOrPrivateKey = secret.private
    secretOrPublicKey = secret.public
  } else {
    secretOrPrivateKey = secretOrPublicKey = secret
  }

  let secretCallbackSign = secretOrPrivateKey
  let secretCallbackVerify = secretOrPublicKey
  if (typeof secretCallbackSign !== 'function') {
    secretCallbackSign = wrapStaticSecretInCallback(secretCallbackSign)
  }
  if (typeof secretCallbackVerify !== 'function') {
    secretCallbackVerify = wrapStaticSecretInCallback(secretCallbackVerify)
  }

  const signOptions = convertTemporalProps(initialSignOptions)
  const verifyOptions = convertTemporalProps(initialVerifyOptions, true)
  const messagesOptions = Object.assign({}, messages, pluginOptions.messages)
  const namespace = typeof pluginOptions.namespace === 'string' ? pluginOptions.namespace : undefined

  if (
    signOptions &&
    signOptions.algorithm &&
    signOptions.algorithm.includes('RS') &&
    (typeof secret === 'string' ||
      secret instanceof Buffer)
  ) {
    return next(new Error('RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
  }
  if (
    signOptions &&
    signOptions.algorithm &&
    signOptions.algorithm.includes('ES') &&
    (typeof secret === 'string' ||
      secret instanceof Buffer)
  ) {
    return next(new Error('ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret'))
  }

  const jwtDecorator = {
    decode: decode,
    options: {
      decode: decodeOptions,
      sign: initialSignOptions,
      verify: initialVerifyOptions,
      messages: messagesOptions
    },
    cookie: cookie,
    sign: sign,
    verify: verify,
    lookupToken: lookupToken
  }

  let jwtDecodeName = 'jwtDecode'
  let jwtVerifyName = 'jwtVerify'
  let jwtSignName = 'jwtSign'
  if (namespace) {
    if (!fastify.jwt) {
      fastify.decorateRequest('user', null)
      fastify.decorate('jwt', Object.create(null))
    }

    if (fastify.jwt[namespace]) {
      return next(new Error(`JWT namespace already used "${namespace}"`))
    }
    fastify.jwt[namespace] = jwtDecorator

    jwtDecodeName = jwtDecode ? (typeof jwtDecode === 'string' ? jwtDecode : 'jwtDecode') : `${namespace}JwtDecode`
    jwtVerifyName = jwtVerify || `${namespace}JwtVerify`
    jwtSignName = jwtSign || `${namespace}JwtSign`
  } else {
    fastify.decorateRequest('user', null)
    fastify.decorate('jwt', jwtDecorator)
  }

  // Temporary conditional to prevent breaking changes by exposing `jwtDecode`,
  // which already exists in fastify-auth0-verify.
  // If jwtDecode has been requested, or plugin is configured to use a namespace.
  // TODO Remove conditional when fastify-jwt >=4.x.x
  if (jwtDecode || namespace) {
    fastify.decorateRequest(jwtDecodeName, requestDecode)
  }
  fastify.decorateRequest(jwtVerifyName, requestVerify)
  fastify.decorateReply(jwtSignName, replySign)

  const signerConfig = checkAndMergeSignOptions()
  const signer = createSigner(signerConfig.options)
  const decoder = createDecoder(decodeOptions)
  const verifierConfig = checkAndMergeVerifyOptions()
  const verifier = createVerifier(verifierConfig.options)

  next()

  function decode (token, options) {
    assert(token, 'missing token')

    if (options && typeof options !== 'function') {
      const localDecoder = createDecoder(options)
      return localDecoder(token)
    }

    return decoder(token)
  }

  function lookupToken (request, options) {
    assert(request, 'missing request')

    options = Object.assign({}, verifyOptions, options)

    let token
    const extractToken = options.extractToken
    if (extractToken) {
      token = extractToken(request)
      if (!token) {
        throw new BadRequest(messagesOptions.badRequestErrorMessage)
      }
    } else if (request.headers && request.headers.authorization) {
      const parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        token = parts[1]

        if (!/^Bearer$/i.test(scheme)) {
          throw new BadRequest(messagesOptions.badRequestErrorMessage)
        }
      } else {
        throw new BadRequest(messagesOptions.badRequestErrorMessage)
      }
    } else if (cookie) {
      if (request.cookies) {
        if (request.cookies[cookie.cookieName]) {
          const tokenValue = request.cookies[cookie.cookieName]

          token = cookie.signed ? request.unsignCookie(tokenValue).value : tokenValue
        } else {
          throw new Unauthorized(messagesOptions.noAuthorizationInCookieMessage)
        }
      } else {
        throw new BadRequest(messagesOptions.badCookieRequestErrorMessage)
      }
    } else {
      throw new Unauthorized(messagesOptions.noAuthorizationInHeaderMessage)
    }

    return token
  }

  function mergeOptionsWithKey (options, useProvidedPrivateKey) {
    if (useProvidedPrivateKey && (typeof useProvidedPrivateKey !== 'boolean')) {
      return Object.assign({}, options, { key: useProvidedPrivateKey })
    } else {
      const key = useProvidedPrivateKey ? secretOrPrivateKey : secretOrPublicKey
      return Object.assign(!options.key ? { key } : {}, options)
    }
  }

  function checkAndMergeOptions (options, defaultOptions, usePrivateKey, callback) {
    if (typeof options === 'function') {
      return { options: mergeOptionsWithKey(defaultOptions, usePrivateKey), callback: options }
    }

    return { options: mergeOptionsWithKey(options || defaultOptions, usePrivateKey), callback }
  }

  function checkAndMergeSignOptions (options, callback) {
    return checkAndMergeOptions(options, signOptions, true, callback)
  }

  function checkAndMergeVerifyOptions (options, callback) {
    return checkAndMergeOptions(options, verifyOptions, false, callback)
  }

  function sign (payload, options, callback) {
    assert(payload, 'missing payload')
    let localSigner = signer

    const localOptions = convertTemporalProps(options)
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

    const localOptions = convertTemporalProps(options, true)
    const veriferConfig = checkAndMergeVerifyOptions(localOptions, callback)

    if (options && typeof options !== 'function') {
      localVerifier = createVerifier(veriferConfig.options)
    }

    if (typeof veriferConfig.callback === 'function') {
      const result = localVerifier(token)
      veriferConfig.callback(null, result)
    } else {
      return localVerifier(token)
    }
  }

  function replySign (payload, options, next) {
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
        sign: mergeOptionsWithKey(Object.assign(signOptions, localSignOptions), true)
      }
    } else {
      const localOptions = convertTemporalProps(options)
      // Original contract, options supports only sign
      options = mergeOptionsWithKey(Object.assign(signOptions, localOptions), true)
    }

    if (!payload) {
      return next(new Error('jwtSign requires a payload'))
    }

    steed.waterfall([
      function getSecret (callback) {
        const signResult = secretCallbackSign(reply.request, payload, callback)

        if (signResult && typeof signResult.then === 'function') {
          signResult.then(result => callback(null, result), callback)
        }
      },
      function sign (secretOrPrivateKey, callback) {
        if (useLocalSigner) {
          const signerOptions = mergeOptionsWithKey(options.sign || options, secretOrPrivateKey)
          const localSigner = createSigner(signerOptions)
          const token = localSigner(payload)
          callback(null, token)
        } else {
          const token = signer(payload)
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
    let useLocalVerifier = true

    if (typeof options === 'function' && !next) {
      next = options
      options = {}
      useLocalVerifier = false
    } // support no options

    if (!options) {
      options = {}
      useLocalVerifier = false
    }

    if (options.decode || options.verify) {
      const localVerifyOptions = convertTemporalProps(options.verify, true)
      // New supported contract, options supports both decode and verify
      options = {
        decode: Object.assign({}, decodeOptions, options.decode),
        verify: Object.assign({}, verifyOptions, localVerifyOptions)
      }
    } else {
      const localOptions = convertTemporalProps(options, true)
      // Original contract, options supports only verify
      options = Object.assign({}, verifyOptions, localOptions)
    }

    const request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request[jwtVerifyName](options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    let token
    try {
      token = lookupToken(request, options.verify || options)
    } catch (err) {
      return next(err)
    }

    const decodedToken = decode(token, options.decode || decodeOptions)

    steed.waterfall([
      function getSecret (callback) {
        const verifyResult = secretCallbackVerify(request, decodedToken, callback)
        if (verifyResult && typeof verifyResult.then === 'function') {
          verifyResult.then(result => callback(null, result), callback)
        }
      },
      function verify (secretOrPublicKey, callback) {
        try {
          if (useLocalVerifier) {
            const verifierOptions = mergeOptionsWithKey(options.verify || options, secretOrPublicKey)
            const localVerifier = createVerifier(verifierOptions)
            const verifyResult = localVerifier(token)
            callback(null, verifyResult)
          } else {
            const verifyResult = verifier(token)
            callback(null, verifyResult)
          }
        } catch (error) {
          if (error.code === TokenError.codes.expired) {
            return callback(new Unauthorized(messagesOptions.authorizationTokenExpiredMessage))
          }

          if (error.code === TokenError.codes.invalidKey ||
              error.code === TokenError.codes.invalidSignature ||
              error.code === TokenError.codes.invalidClaimValue
          ) {
            return callback(new Unauthorized(typeof messagesOptions.authorizationTokenInvalid === 'function' ? messagesOptions.authorizationTokenInvalid(error) : messagesOptions.authorizationTokenInvalid))
          }

          return callback(error)
        }
      },
      function checkIfIsTrusted (result, callback) {
        if (!trusted) {
          callback(null, result)
        } else {
          const maybePromise = trusted(request, result)

          if (maybePromise && maybePromise.then) {
            maybePromise
              .then(trusted => trusted ? callback(null, result) : callback(new Unauthorized(messagesOptions.authorizationTokenUntrusted)))
          } else if (maybePromise) {
            callback(null, maybePromise)
          } else {
            callback(new Unauthorized(messagesOptions.authorizationTokenUntrusted))
          }
        }
      }
    ], function (err, result) {
      if (err) {
        next(err)
      } else {
        const user = formatUser ? formatUser(result) : result
        request.user = user
        next(null, user)
      }
    })
  }
}

module.exports = fp(fastifyJwt, {
  fastify: '>=3.0.0',
  name: 'fastify-jwt'
})
