'use strict'

const fp = require('fastify-plugin')
const jwt = require('jsonwebtoken')
const assert = require('assert')
const steed = require('steed')
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

function fastifyJwt (fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  if (options.options) {
    return next(new Error('options prefix is deprecated'))
  }

  const secret = options.secret
  const trusted = options.trusted
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

  const cookie = options.cookie
  const formatUser = options.formatUser

  const decodeOptions = options.decode || {}
  const signOptions = options.sign || {}
  const verifyOptions = options.verify || {}
  const messagesOptions = Object.assign({}, messages, options.messages)
  const namespace = typeof options.namespace === 'string' ? options.namespace : undefined

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

  const jwtConfig = {
    decode: decode,
    options: {
      decode: decodeOptions,
      sign: signOptions,
      verify: verifyOptions,
      messages: messagesOptions
    },
    cookie: cookie,
    sign: sign,
    verify: verify
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
    fastify.jwt[namespace] = jwtConfig

    jwtDecodeName = options.jwtDecode ? (typeof options.jwtDecode === 'string' ? options.jwtDecode : 'jwtDecode') : `${namespace}JwtDecode`
    jwtVerifyName = options.jwtVerify || `${namespace}JwtVerify`
    jwtSignName = options.jwtSign || `${namespace}JwtSign`
  } else {
    fastify.decorateRequest('user', null)
    fastify.decorate('jwt', jwtConfig)
  }

  // Temporary conditional to prevent breaking changes by exposing `jwtDecode`,
  // which already exists in fastify-auth0-verify.
  // If jwtDecode has been requested, or plugin is configured to use a namespace.
  // TODO Remove conditional when fastify-jwt >=4.x.x
  if (options.jwtDecode || namespace) {
    fastify.decorateRequest(jwtDecodeName, requestDecode)
  }
  fastify.decorateRequest(jwtVerifyName, requestVerify)
  fastify.decorateReply(jwtSignName, replySign)

  next()

  function decode (token, options) {
    assert(token, 'missing token')

    if (!options) {
      options = Object.assign({}, decodeOptions)
    }

    return jwt.decode(token, options)
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

  function sign (payload, options, callback) {
    assert(payload, 'missing payload')

    if (typeof options === 'function') {
      callback = options
      options = Object.assign({}, signOptions)
    }

    if (!options) {
      options = Object.assign({}, signOptions)
    }

    if (typeof callback === 'function') {
      jwt.sign(payload, secretOrPrivateKey, options, callback)
    } else {
      return jwt.sign(payload, secretOrPrivateKey, options)
    }
  }

  function verify (token, options, callback) {
    assert(token, 'missing token')
    assert(secretOrPublicKey, 'missing secret')

    if ((typeof options === 'function') && !callback) {
      callback = options
      options = Object.assign({}, verifyOptions)
    }

    if (!options) {
      options = Object.assign({}, verifyOptions)
    }

    if (typeof callback === 'function') {
      jwt.verify(token, secretOrPublicKey, options, callback)
    } else {
      return jwt.verify(token, secretOrPublicKey, options)
    }
  }

  function replySign (payload, options, next) {
    if (typeof options === 'function') {
      next = options
      options = {}
    } // support no options

    if (!options) {
      options = {}
    }

    if (options.sign) {
      // New supported contract, options supports sign and can expand
      options = {
        sign: Object.assign({}, signOptions, options.sign)
      }
    } else {
      // Original contract, options supports only sign
      options = Object.assign({}, signOptions, options)
    }

    const reply = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        reply[jwtSignName](payload, options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
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
        jwt.sign(payload, secretOrPrivateKey, options.sign || options, callback)
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
    if (typeof options === 'function' && !next) {
      next = options
      options = {}
    } // support no options

    if (!options) {
      options = {}
    }

    if (options.decode || options.verify) {
      // New supported contract, options supports both decode and verify
      options = {
        decode: Object.assign({}, decodeOptions, options.decode),
        verify: Object.assign({}, verifyOptions, options.verify)
      }
    } else {
      // Original contract, options supports only verify
      options = Object.assign({}, verifyOptions, options)
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
        jwt.verify(token, secretOrPublicKey, options.verify || options, (err, result) => {
          if (err instanceof jwt.TokenExpiredError) {
            return callback(new Unauthorized(messagesOptions.authorizationTokenExpiredMessage))
          }
          if (err instanceof jwt.JsonWebTokenError) {
            return callback(new Unauthorized(typeof messagesOptions.authorizationTokenInvalid === 'function' ? messagesOptions.authorizationTokenInvalid(err) : messagesOptions.authorizationTokenInvalid))
          }
          callback(err, result)
        })
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
  fastify: '>=3.0.0-alpha.1',
  name: 'fastify-jwt'
})
