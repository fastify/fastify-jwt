'use strict'

var fp = require('fastify-plugin')
var JWT = require('jsonwebtoken')
var assert = require('assert')
var steed = require('steed')

function wrapStaticSecretInCallback (secret) {
  return function (request, payload, cb) {
    return cb(null, secret)
  }
}

function fastifyJwt (fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  var secret = options.secret
  var secretCallback = secret
  if (typeof secretCallback !== 'function') { secretCallback = wrapStaticSecretInCallback(secretCallback) }

  fastify.decorate('jwt', {
    decode: decode,
    sign: sign,
    verify: verify,
    secret: options.secret
  })

  fastify.decorateReply('jwtSign', replySign)

  fastify.decorateRequest('jwtVerify', requestVerify)

  next()

  function sign (payload, options, callback) {
    assert(payload, 'missing payload')
    options = options || {}
    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    if (typeof callback === 'function') {
      JWT.sign(payload, secret, options, callback)
    } else {
      return JWT.sign(payload, secret, options)
    }
  }

  function verify (token, options, callback) {
    assert(token, 'missing token')
    assert(secret, 'missing secret')
    options = options || {}
    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    if (typeof callback === 'function') {
      JWT.verify(token, secret, options, callback)
    } else {
      return JWT.verify(token, secret, options)
    }
  }

  function decode (token, options) {
    assert(token, 'missing token')
    options = options || {}
    return JWT.decode(token, options)
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
        JWT.sign(payload, secret, options, callback)
      }
    ], next)
  } // end sign

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
          return next(new Error('Format is Authorization: Bearer [token]'))
        }
      }
    } else {
      return next(new Error('No Authorization was found in request.headers'))
    }

    var decodedToken = JWT.decode(token, options)
    steed.waterfall([
      function getSecret (callback) {
        secretCallback(request, decodedToken, callback)
      },
      function verify (secret, callback) {
        JWT.verify(token, secret, options, callback)
      }
    ], function (err, result) {
      if (err) next(err)
      request.user = result
      next(null, result)
    })
  } // end verify
}

module.exports = fp(fastifyJwt, {
  fastify: '>=1.0.0-rc.1',
  name: 'fastify-jwt'
})
