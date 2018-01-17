'use strict'

const fp = require('fastify-plugin')
const JWT = require('jsonwebtoken')
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

  let secretCallback = options.secret

  if (typeof secretCallback !== 'function') { secretCallback = wrapStaticSecretInCallback(secretCallback) }

  fastify.decorate('jwt', {
    decode: decode,
    sign: sign,
    verify: verify,
    secretCallback: secretCallback
  })

  next()

  function decode (token, options = {}) {
    if (!token) {
      throw new Error('missing token')
    }

    return JWT.decode(token, options)
  }

  function sign (request, reply, next) {
    let {secret, ...rest} = options
    steed.waterfall([
      function getSecret (callback) {
        secretCallback(request, {}, callback)
      },
      function sign (secret, callback) {
        JWT.sign(request.body, secret, rest, callback)
      }
    ], next)
  } // end sign

  function verify (request, reply, next) {
    let token
    if (request.headers && request.headers.authorization) {
      const parts = request.headers.authorization.split(' ')
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
        secretCallback(request, decodedToken, callback)
      },
      function verify (secret, callback) {
        JWT.verify(token, secret, options, callback)
      }
    ], next)
  } // end verify
}

module.exports = fp(fastifyJwt, '>= 0.39')
