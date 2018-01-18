'use strict'

var test = require('tap').test
var Fastify = require('fastify')
var rp = require('request-promise-native')
var jwt = require('./jwt')

test('fastify-jwt should expose jwt methods', function (t) {
  t.plan(8)
  var fastify = Fastify()
  fastify
    .register(jwt, { secret: 'supersecret' })
    .ready(function () {
      t.ok(fastify.jwt.decode)
      t.ok(fastify.jwt.sign)
      t.ok(fastify.jwt.verify)
      t.ok(fastify.jwt.secret)
    })
  fastify.get('/test', function (request, reply) {
    t.ok(request.jwtVerify)
    t.ok(reply.jwtSign)
    reply.send({ foo: 'bar' })
  })
  fastify.listen(0, function (err) {
    fastify.server.unref()
    t.error(err)
    rp({
      method: 'GET',
      uri: 'http://localhost:' + fastify.server.address().port + '/test',
      json: true
    }).then(function (response) {
      t.ok(response)
    }).catch(function (err) {
      t.fail(err)
    })
  })
})

test('fastify-jwt fails without secret', function (t) {
  t.plan(1)
  var fastify = Fastify()
  fastify
    .register(jwt)
    .listen(0, function (err) {
      t.is(err.message, 'missing secret')
    })
})

test('sign and verify', function (t) {
  t.plan(7)
  var fastify = Fastify()
  fastify.register(jwt, { secret: 'supersecret' })

  fastify.post('/sign', function (request, reply) {
    reply.jwtSign(request.body.payload, function (err, token) {
      if (err) { return reply.send(err) }
      return reply.send({ 'token': token })
    })
  })

  fastify.get('/verify', function (request, reply) {
    request.jwtVerify(function (err, decoded) {
      if (err) { return reply.send(err) }
      return reply.send(decoded)
    })
  })

  fastify.listen(0, function (err) {
    fastify.server.unref()
    t.error(err)
  })

  t.test('syncronously', function (t) {
    t.plan(1)
    fastify.ready(function () {
      var token = fastify.jwt.sign({ foo: 'bar' })
      var decoded = fastify.jwt.verify(token)
      t.is(decoded.foo, 'bar')
    })
  })

  t.test('asynchronously', function (t) {
    t.plan(5)
    fastify.ready(function () {
      fastify.jwt.sign({ foo: 'bar' }, function (err, token) {
        t.error(err)
        t.ok(token)
        fastify.jwt.verify(token, function (err, decoded) {
          t.error(err)
          t.ok(decoded)
          t.is(decoded.foo, 'bar')
        })
      })
    })
  })

  t.test('jwtSign and jwtVerify', function (t) {
    t.plan(2)

    rp({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        payload: {
          foo: 'bar'
        }
      },
      uri: 'http://localhost:' + fastify.server.address().port + '/sign',
      json: true
    }).then(function (sign) {
      rp({
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer ' + sign.token
        },
        uri: 'http://localhost:' + fastify.server.address().port + '/verify',
        json: true
      }).then(function (verify) {
        t.ok(verify)
        t.is(verify.foo, 'bar')
      }).catch(function (err) {
        t.fail(err.message)
      })
    }).catch(function (err) {
      t.fail(err.message)
    })
  })

  t.test('jwtVerify throws No Authorization error', function (t) {
    t.plan(1)
    rp({
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
      uri: 'http://localhost:' + fastify.server.address().port + '/verify',
      json: true
    }).then(function () {
      t.fail()
    }).catch(function (err) {
      t.is(err.error.message, 'No Authorization was found in request.headers')
    })
  })

  t.test('jwtVerify throws Authorization Format error', function (t) {
    t.plan(1)
    rp({
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        authorization: 'Invalid TokenFormat'
      },
      uri: 'http://localhost:' + fastify.server.address().port + '/verify',
      json: true
    }).then(function () {
      t.fail()
    }).catch(function (err) {
      t.is(err.error.message, 'Format is Authorization: Bearer [token]')
    })
  })

  t.test('jwtSign throws payload error', function (t) {
    t.plan(1)
    rp({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        notAPayload: 'sorry'
      }),
      uri: 'http://localhost:' + fastify.server.address().port + '/sign',
      json: true
    }).then(function () {
      t.fail()
    }).catch(function (err) {
      t.is(err.error.message, 'jwtSign requires a payload')
    })
  })
})

test('decode', function (t) {
  t.plan(1)
  var fastify = Fastify()
  fastify.register(jwt, { secret: 'shh' }).ready(function () {
    var token = fastify.jwt.sign({ foo: 'bar' })
    var decoded = fastify.jwt.decode(token)
    t.is(decoded.foo, 'bar')
  })
})

test('secret as a function', function (t) {
  t.plan(4)
  var fastify = Fastify()
  fastify
    .register(jwt, {
      secret: function (request, reply, callback) {
        callback(null, 'supersecret')
      }
    })

  fastify.post('/sign', function (request, reply) {
    reply.jwtSign(request.body.payload, function (err, token) {
      if (err) { return reply.send(err) }
      return reply.send({token})
    })
  })

  fastify.get('/verify', function (request, reply) {
    request.jwtVerify(function (err, decoded) {
      if (err) { return reply.send(err) }
      return reply.send(decoded)
    })
  })

  fastify.listen(0, function (err) {
    fastify.server.unref()
    t.error(err)
    rp({
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        payload: {
          foo: 'bar'
        }
      },
      uri: 'http://localhost:' + fastify.server.address().port + '/sign',
      json: true
    }).then(function (sign) {
      t.ok(sign)
      rp({
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          authorization: 'Bearer ' + sign.token
        },
        uri: 'http://localhost:' + fastify.server.address().port + '/verify',
        json: true
      }).then(function (verify) {
        t.ok(verify)
        t.is(verify.foo, 'bar')
      }).catch(function (err) {
        t.fail(err)
      })
    }).catch(function (err) {
      t.fail(err)
    })
  })
})
