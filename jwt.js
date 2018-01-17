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

  function parseToken (request, next) {
    if (request.headers && request.headers.authorization) {
      const parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        const token = parts[1]

        if (/^Bearer$/i.test(scheme)) {
          return next(null, token)
        }
      }
      return next(new Error('Format is Authorization: Bearer [token]'))
    } else {
      return next(new Error('No Authorization was found in request.headers'))
    }
  }

  function decode (token, options = {}, next) {
    if (!token) {
      if (next) { return next(new Error('Missing token')) } else throw new Error('Missing token')
    }

    let decodedToken = JWT.decode(token, options)

    if (next) { return next(null, decodedToken) } else return decodedToken
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
    steed.waterfall([
      function getToken (callback) {
        parseToken(request, callback)
      },
      function decodeToken (token, callback) {
        decode(token, (err, decodedToken) => {
          callback(err, token, decodedToken)
        })
      },
      function getSecret (token, decodedToken, callback) {
        secretCallback(request, decodedToken, (err, secret) => {
          callback(err, secret, token)
        })
      },
      function verify (secret, token, callback) {
        JWT.verify(token, secret, options, callback)
      }
    ], next)
  } // end verify
}

module.exports = fp(fastifyJwt, '>= 0.39')
