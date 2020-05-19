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
  if (typeof secretCallbackSign !== 'function') { secretCallbackSign = wrapStaticSecretInCallback(secretCallbackSign) }
  if (typeof secretCallbackVerify !== 'function') { secretCallbackVerify = wrapStaticSecretInCallback(secretCallbackVerify) }

  const cookie = options.cookie

  const decodeOptions = options.decode || {}
  const signOptions = options.sign || {}
  const verifyOptions = options.verify || {}
  const messagesOptions = Object.assign({}, messages, options.messages)

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

  fastify.decorate('jwt', {
    decode: decode,
    options: {
      decode: decodeOptions,
      sign: signOptions,
      verify: verifyOptions,
      messages: messagesOptions
    },
    cookie: cookie,
    secret: secret,
    sign: sign,
    verify: verify
  })
  fastify.decorateRequest('jwtVerify', requestVerify)
  fastify.decorateReply('jwtSign', replySign)

  next()

  function decode (token, options) {
    assert(token, 'missing token')

    if (!options) {
      options = Object.assign({}, decodeOptions)
    }

    return jwt.decode(token, options)
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
      options = Object.assign({}, signOptions)
    } // support no options

    if (!options) {
      options = Object.assign({}, signOptions)
    }

    const reply = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        reply.jwtSign(payload, options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    if (!payload) {
      return next(new Error('jwtSign requires a payload'))
    }

    steed.waterfall([
      function getSecret (callback) {
        secretCallbackSign(reply.request, payload, callback)
      },
      function sign (secretOrPrivateKey, callback) {
        jwt.sign(payload, secretOrPrivateKey, options, callback)
      }
    ], next)
  }

  function requestVerify (options, next) {
    if (typeof options === 'function' && !next) {
      next = options
      options = Object.assign({}, verifyOptions)
    } // support no options

    if (!options) {
      options = Object.assign({}, verifyOptions)
    }

    const request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request.jwtVerify(options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    let token
    const extractToken = options.extractToken
    if (extractToken) {
      token = extractToken(request)
      if (!token) {
        return next(new BadRequest(messagesOptions.badRequestErrorMessage))
      }
    } else if (request.headers && request.headers.authorization) {
      const parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        token = parts[1]

        if (!/^Bearer$/i.test(scheme)) {
          return next(new BadRequest(messagesOptions.badRequestErrorMessage))
        }
      } else {
        return next(new BadRequest(messagesOptions.badRequestErrorMessage))
      }
    } else if (cookie) {
      if (request.cookies) {
        if (request.cookies[cookie.cookieName]) {
          token = request.cookies[cookie.cookieName]
        } else {
          return next(new Unauthorized(messagesOptions.noAuthorizationInCookieMessage))
        }
      } else {
        return next(new BadRequest(messagesOptions.badCookieRequestErrorMessage))
      }
    } else {
      return next(new Unauthorized(messagesOptions.noAuthorizationInHeaderMessage))
    }

    const decodedToken = jwt.decode(token, decodeOptions)

    steed.waterfall([
      function getSecret (callback) {
        secretCallbackVerify(request, decodedToken, callback)
      },
      function verify (secretOrPublicKey, callback) {
        jwt.verify(token, secretOrPublicKey, options, (err, result) => {
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
        request.user = result
        next(null, result)
      }
    })
  }
}

module.exports = fp(fastifyJwt, {
  fastify: '>=3.0.0-alpha.1',
  name: 'fastify-jwt'
})
