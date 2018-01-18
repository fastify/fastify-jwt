'use strict'

const fp = require('fastify-plugin')
const JWT = require('jsonwebtoken')
const assert = require('assert')
const steed = require('steed')

function wrapStaticSecretInCallback (secret) {
  return function (_, __, cb) {
    return cb(null, secret)
  }
}

function fastifyJwt (fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  let secret = options.secret
  let secretCallback = secret
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
    if (!payload) {
      return next(new Error('jwtSign requires a payload'))
    }
    steed.waterfall([
      function getSecret (callback) {
        secretCallback(null, null, callback)
      },
      function sign (secret, callback) {
        JWT.sign(payload, secret, options, callback)
      }
    ], (err, token) => {
      if (err) return next(err)
      return next(null, token)
    })
  } // end sign

  function requestVerify (options = {}, next) {
    if (typeof options === 'function') {
      next = options
      options = {}
    } // support no options
    let token
    if (this.headers && this.headers.authorization) {
      const parts = this.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        token = parts[1]

        if (!/^Bearer$/i.test(scheme)) {
          return next(new Error('Format is Authorization: Bearer [token]'))
        }
      }
    } else {
      return next(new Error('No Authorization was found in request.headers'))
    }

    let decodedToken = JWT.decode(token, options)
    steed.waterfall([
      function getSecret (callback) {
        secretCallback(this, decodedToken, callback)
      },
      function verify (secret, callback) {
        JWT.verify(token, secret, options, callback)
      }
    ], next)
  } // end verify
}

module.exports = fp(fastifyJwt, '>= 0.39')
