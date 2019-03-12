'use strict'

const fp = require('fastify-plugin')
const jwt = require('jsonwebtoken')
const assert = require('assert')
const steed = require('steed')
const {
  BadRequest,
  Unauthorized
} = require('http-errors')

const badRequestErrorMessage = 'Format is Authorization: Bearer [token]'

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

  const decodeOptions = options.decode || {}
  const signOptions = options.sign || {}
  const verifyOptions = options.verify || {}

  if (
    signOptions &&
    signOptions.algorithm &&
    signOptions.algorithm.includes('RS') &&
    typeof secret === 'string'
  ) {
    return next(new Error(`RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret`))
  }
  if (
    signOptions &&
    signOptions.algorithm &&
    signOptions.algorithm.includes('ES') &&
    typeof secret === 'string'
  ) {
    return next(new Error(`ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret`))
  }

  fastify.decorate('jwt', {
    decode: decode,
    options: {
      decode: decodeOptions,
      sign: signOptions,
      verify: verifyOptions
    },
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
    if (request.headers && request.headers.authorization) {
      let parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        let scheme = parts[0]
        token = parts[1]

        if (!/^Bearer$/i.test(scheme)) {
          return next(new BadRequest(badRequestErrorMessage))
        }
      } else {
        return next(new BadRequest(badRequestErrorMessage))
      }
    } else {
      return next(new Unauthorized('No Authorization was found in request.headers'))
    }

    let decodedToken = jwt.decode(token, decodeOptions)

    steed.waterfall([
      function getSecret (callback) {
        secretCallbackVerify(request, decodedToken, callback)
      },
      function verify (secretOrPublicKey, callback) {
        jwt.verify(token, secretOrPublicKey, options, (err, result) => {
          if (err instanceof jwt.TokenExpiredError) {
            return callback(new Unauthorized('Authorization token expired'))
          }
          if (err instanceof jwt.JsonWebTokenError) {
            return callback(new Unauthorized('Authorization token is invalid: ' + err.message))
          }
          callback(err, result)
        })
      }
    ], function (err, result) {
      if (err) next(err)
      request.user = result
      next(null, result)
    })
  }
}

module.exports = fp(fastifyJwt, {
  fastify: '>=1.0.0',
  name: 'fastify-jwt'
})
