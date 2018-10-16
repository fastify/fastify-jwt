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
  var secretKey, secretPass
  if (!options.secret) {
    return next(new Error('missing secret'))
  }
  var secret = options.secret

  if (typeof secret === 'object') {
    if (!secret.key || !secret.passphrase) {
      return next(new Error('missing secret key and/or passphrase'))
    }
    secretKey = secret.key
    secretPass = secret.passphrase
  } else {
    secretKey = secretPass = secret
  }
  var secretCallback = secret
  if (typeof secretCallback !== 'function') { secretCallback = wrapStaticSecretInCallback(secretCallback) }

  var defaultOptions = options.options || {}

  if (defaultOptions && defaultOptions.algorithm && defaultOptions.algorithm.includes('RS') && typeof secret === 'string') {
    return next(new Error(`RSA Signatures set as Algorithm in the options require a key and passphrase to be set as the secret`))
  }

  fastify.decorate('jwt', {
    decode: decode,
    sign: sign,
    verify: verify,
    secret: options.secret
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
    signOptions = Object.assign(defaultOptions, signOptions)
    delete signOptions['algorithms']

    if (typeof callback === 'function') {
      jwt.sign(payload, secretKey, signOptions, callback)
    } else {
      return jwt.sign(payload, secretKey, signOptions)
    }
  }

  function verify (token, verifyOptions, callback) {
    assert(token, 'missing token')
    assert(secret, 'missing secret')
    verifyOptions = verifyOptions || {}
    if (typeof verifyOptions === 'function') {
      callback = verifyOptions
      verifyOptions = {}
    }
    verifyOptions = Object.assign(defaultOptions, verifyOptions)
    if (typeof callback === 'function') {
      jwt.verify(token, secretPass, verifyOptions, callback)
    } else {
      return jwt.verify(token, secretPass, verifyOptions)
    }
  }

  function decode (token, options) {
    assert(token, 'missing token')
    options = options || {}
    return jwt.decode(token, options)
  }

  function replySign (payload, options, next) {
    if (typeof options === 'function') {
      next = options
      options = {}
    } // support no options
    var reply = this
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
        secretCallback(reply.request, payload, callback)
      },
      function sign (secret, callback) {
        jwt.sign(payload, secret, options, callback)
      }
    ], next)
  }

  function requestVerify (options, next) {
    if (typeof options === 'function') {
      next = options
      options = {}
    } // support no options

    var request = this

    if (next === undefined) {
      return new Promise(function (resolve, reject) {
        request.jwtVerify(options, function (err, val) {
          err ? reject(err) : resolve(val)
        })
      })
    }

    var token
    if (request.headers && request.headers.authorization) {
      var parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        var scheme = parts[0]
        token = parts[1]

        if (!/^Bearer$/i.test(scheme)) {
          return next(new BadRequest('Format is Authorization: Bearer [token]'))
        }
      }
    } else {
      return next(new Unauthorized('No Authorization was found in request.headers'))
    }

    var decodedToken = jwt.decode(token, options)
    steed.waterfall([
      function getSecret (callback) {
        secretCallback(request, decodedToken, callback)
      },
      function verify (secret, callback) {
        jwt.verify(token, secret, options, callback)
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
