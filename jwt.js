const fp = require('fastify-plugin')
const JWT = require('jsonwebtoken')
const steed = require('steed')()

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

  let _requestProperty = options.userProperty || options.requestProperty || 'user'
  let _resultProperty = options.resultProperty
  const credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired

  fastify.decorate('jwt', {
    sign: sign,
    verify: verify,
    secretCallback: secretCallback
  })

  next()

  function getToken (request, cb) {
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
            return cb(new Error('Format is Authorization: Bearer [token]'))
          } else {
            return cb()
          }
        }
      } else {
        return cb(new Error('Format is Authorization: Bearer [token]'))
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return cb(new Error('No authorization token was found'))
      } else {
        return cb()
      }
    }

    return token
  }

  function decodeToken (token, cb) {
    let decodedToken

    try {
      decodedToken = JWT.decode(token, { complete: true }) || {}
    } catch (err) {
      return cb(new Error(`invalid_token ${err}`))
    }

    return decodedToken
  }

  function sign (request, reply, next) {
    let {secret, ...rest} = options
    steed.waterfall([
      function getSecret (callback) {
        secretCallback({}, {}, callback)
      },
      function sign (secret, callback) {
        JWT.sign(request.body, secret, rest, function (err, token) {
          if (err) {
            callback(err)
          } else {
            callback(null, token)
          }
        })
      }
    ], function (err, result) {
      if (_resultProperty) {
        reply[_resultProperty] = result
      } else {
        request[_requestProperty] = result
      }
      return next(err, result)
    })
  } // end sign

  function verify (request, reply, next) {
    const token = getToken(request, next)
    const decodedToken = decodeToken(token, next)

    steed.waterfall([
      function getSecret (callback) {
        secretCallback(request, decodedToken, callback)
      },
      function verify (secret, callback) {
        JWT.verify(token, secret, options, function (err, decoded) {
          if (err) {
            callback(err)
          } else {
            callback(null, decoded)
          }
        })
      }
    ], function (err, result) {
      if (_resultProperty) {
        reply[_resultProperty] = result
      } else {
        request[_requestProperty] = result
      }
      return next(err, result)
    })
  } // end verify
}

module.exports = fp(fastifyJwt, '0.x')
