'use strict'

const fp = require('fastify-plugin')
const jwt = require('jsonwebtoken')
const assert = require('assert')
const steed = require('steed')
const {
  BadRequest,
  Unauthorized
} = require('http-errors')

function wrapStaticSecretInCallback (secret) {
  return function (request, payload, cb) {
    return cb(null, secret)
  }
}

function fastifyJwt (fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  let secret = options.secret
  let secretOrPrivateKey
  let secretOrPublicKey

  if (typeof secret === 'object') {
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

  let defaultOptions = options.options || {}
  if (
    defaultOptions &&
    defaultOptions.algorithm &&
    defaultOptions.algorithm.includes('RS') &&
    typeof secret === 'string'
  ) {
    return next(new Error(`RSA Signatures set as Algorithm in the options require a private and public key to be set as the secret`))
  }
  if (
    defaultOptions &&
    defaultOptions.algorithm &&
    defaultOptions.algorithm.includes('ES') &&
    typeof secret === 'string'
  ) {
    return next(new Error(`ECDSA Signatures set as Algorithm in the options require a private and public key to be set as the secret`))
  }

  fastify.decorate('jwt', {
    decode: decode,
    sign: sign,
    verify: verify,
    secret: secret
  })

  fastify.decorateReply('jwtSign', replySign)

  fastify.decorateRequest('jwtVerify', requestVerify)

  next()

  function sign (payload, signOptions, callback) {
    assert(payload, 'missing payload')

    signOptions = signOptions || {}
    if (typeof signOptions === 'function') {
      callback = signOptions
      signOptions = {}
    }
    signOptions = Object.assign({}, defaultOptions)
    delete signOptions['algorithms']

    if (typeof callback === 'function') {
      jwt.sign(payload, secretOrPrivateKey, signOptions, callback)
    } else {
      return jwt.sign(payload, secretOrPrivateKey, signOptions)
    }
  }

  function verify (token, verifyOptions, callback) {
    assert(token, 'missing token')
    assert(secret, 'missing secret')

    verifyOptions = verifyOptions || {}
    if ((typeof verifyOptions === 'function') && !callback) {
      callback = verifyOptions
      verifyOptions = {}
    }
    verifyOptions = Object.assign({}, defaultOptions)

    if (typeof callback === 'function') {
      jwt.verify(token, secretOrPublicKey, verifyOptions, callback)
    } else {
      return jwt.verify(token, secretOrPublicKey, verifyOptions)
    }
  }

  function decode (token, options) {
    assert(token, 'missing token')
    options = options || {}
    return jwt.decode(token, options)
  }

  function replySign (payload, signOptions, next) {
    if (typeof signOptions === 'function') {
      next = signOptions
      signOptions = {}
    } // support no options
    signOptions = Object.assign({}, defaultOptions)
    delete signOptions['algorithms']

    let reply = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        reply.jwtSign(payload, signOptions, function (err, val) {
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
        jwt.sign(payload, secretOrPrivateKey, signOptions, callback)
      }
    ], next)
  }

  function requestVerify (verifyOptions, next) {
    if (typeof verifyOptions === 'function') {
      next = verifyOptions
      verifyOptions = {}
    } // support no options
    verifyOptions = Object.assign({}, defaultOptions)

    let request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request.jwtVerify(verifyOptions, function (err, val) {
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
          return next(new BadRequest('Format is Authorization: Bearer [token]'))
        }
      }
    } else {
      return next(new Unauthorized('No Authorization was found in request.headers'))
    }

    let decodedToken = jwt.decode(token, options)

    steed.waterfall([
      function getSecret (callback) {
        secretCallbackVerify(request, decodedToken, callback)
      },
      function verify (secretOrPublicKey, callback) {
        jwt.verify(token, secretOrPublicKey, verifyOptions, callback)
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
