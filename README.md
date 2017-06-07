# fastify-jwt

[![js-standard-style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat)](http://standardjs.com/)  [![Build Status](https://travis-ci.org/fastify/fastify-jwt.svg?branch=master)](https://travis-ci.org/fastify/fastify-jwt)

JWT utils for Fastify, internally uses [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Install
```
npm i fastify-jwt --save
```

## Usage
Register it as plugin and then access it via `jwt`.  
The api is the same of [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken), refer to their documentation to find how use the utilities.

```js
const fastify = require('fastify')
fastify.register(require('fastify-jwt'), { secret: 'supersecret' }, err => {
  if (err) throw err
})

fastify.post('/signup', (req, reply) => {
  // some code
  const token = fastify.jwt.sign({ payload })
  reply.send({ token })
})

fastify.listen(3000, err => {
  if (err) throw err
})
```

## Acknowledgements

This project is kindly sponsored by:
- [LetzDoIt](http://www.letzdoitapp.com/)

## License

Licensed under [MIT](./LICENSE).
