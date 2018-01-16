const fp = require('fastify-plugin')
const JWT = require('jsonwebtoken')
const assert = require('assert')
const waterfall = require('async/waterfall')

function isFunction(object) {
  return Object.prototype.toString.call(object) === '[object Function]'
}

function wrapStaticSecretInCallback(secret){
  return function(_, __, cb) { // _ = req, __ = res
    return cb(null, secret) 
  }
}

function fastifyJwt(fastify, options, next) {
  if (!options.secret) {
    return next(new Error('missing secret'))
  }

  let secretCallback = options.secret

  if(!isFunction(secretCallback)) 
    secretCallback = wrapStaticSecretInCallback(secretCallback)
  
  let _requestProperty = options.userProperty || options.requestProperty || 'user'
  let _resultProperty = options.resultProperty
  const credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired
  
  fastify.decorate('jwt', {
    sign: sign,
    verify: verify,
  })

  next() 

  function sign (request, reply, next) {

    JWT.sign(request.body, secret, options, callback)
  } // end sign 

  function verify (request, reply, next) {
    let token

    if (request.headers && request.headers.authorization) {
      const parts = request.headers.authorization.split(' ')
      if (parts.length === 2) {
        const scheme = parts[0]
        const credentials = parts[1]

        if (/^Bearer$/i.test(scheme)) {
          token = credentials
        } else {
          if (credentialsRequired) {
            return next(new Error('Format is Authorization: Bearer [token]'))
          } else {
            return next()
          }
        }
      } else {
        return next(new Error('Format is Authorization: Bearer [token]'))
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new Error('No authorization token was found'))
      } else {
        return next()
      }
    }

    let decoded_token

    try {
      decoded_token = JWT.decode(token, { complete: true }) || {}
    } catch(err) {
      return next(new Error(`invalid_token ${err}`))
    }

    waterfall([
      function getSecret(callback) {
        secretCallback(request, decoded_token, callback)
      },
      function verify(secret, callback) {
        JWT.verify(token, secret, options, function(err, decoded) {
          if (err) {
            callback(err)
          } else {
            callback(null, decoded)
          }
        })
      }
    ], function (err, result) {
      if (err) { return next(err) }
      if (_resultProperty) {
        reply[_resultProperty] = result
      } else {
        request[_requestProperty] = result
      }
      next()
    })
  } // end verify
}

module.exports = fp(fastifyJwt, '0.x')