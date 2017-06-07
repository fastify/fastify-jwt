'use strict'

const fp = require('fastify-plugin')
const JWT = require('jsonwebtoken')
const assert = require('assert')

function fastifyJWT (fastify, opts, next) {
  if (!opts.secret) {
    return next(new Error('missing secret'))
  }

  const secret = opts.secret

  fastify.decorate('jwt', {
    sign: sign,
    verify: verify,
    decode: decode,
    secret: secret
  })

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
}

module.exports = fp(fastifyJWT, '>=0.13.1')
