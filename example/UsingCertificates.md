# Certificates generation

## RSA Signatures - Certificates (without passphrase)

Certificates `private.key` and `public.key` are generated with http://travistidwell.com/jsencrypt/demo/ or with the following command

```sh
openssl genrsa -out private.key 2048
openssl rsa -in private.key -out public.key -outform PEM -pubout
```

Code example

```js
const { readFileSync } = require('fs')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')

fastify.register(jwt, {
  secret: {
    private: readFileSync('path/to/private.key', 'utf8'),
    public: readFileSync('path/to/public.key', 'utf8')
  },
  sign: { algorithm: 'RS256' }
})
```

## RSA Signatures - Certificates (with passphrase)

Certificates `private.pem` and `public.pem` are generated with the following command lines

```sh
# generate a 2048-bit RSA key pair, and encrypts them with a passphrase
# the passphrase I choose for the demo files is: super secret passphrase
openssl genrsa -des3 -out private.pem 2048

# export the RSA public key to a file
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Code example

```js
const { readFileSync } = require('fs')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')

fastify.register(jwt, {
  secret: {
    private: {
      key: readFileSync('path/to/private.pem', 'utf8'),
      passphrase: 'super secret passphrase'
    },
    public: readFileSync('path/to/public.pem', 'utf8')
  },
  sign: { algorithm: 'RS256' }
})
```

## ECDSA Signatures - Certificates (without passphrase)

Certificates `privateECDSA.key` and `publicECDSA.key` are generated with the following command lines

```sh
# generate a P-256 curve ECDSA key pair
openssl ecparam -genkey -name prime256v1 -out privateECDSA.key

# export the ECDSA public key to a file
openssl ec -in privateECDSA.key -pubout -out publicECDSA.key
```

Code example

```js
const { readFileSync } = require('fs')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')

fastify.register(jwt, {
  secret: {
    private: readFileSync('path/to/privateECDSA.key', 'utf8'),
    public: readFileSync('path/to/publicECDSA.key', 'utf8')
  },
  sign: { algorithm: 'ES256' }
})
```

## ECDSA Signatures - Certificates (with passphrase)

Certificates `privateECDSA.pem` and `publicECDSA.pem` are generated with the following command lines

```sh
# generate a P-256 curve ECDSA key pair, and encrypts them with a passphrase
# the passphrase I choose for the demo files is: super secret passphrase
openssl ecparam -genkey -name prime256v1 | openssl ec -aes256 -out privateECDSA.pem

# export the ECDSA public key to a file
openssl ec -in privateECDSA.pem -pubout -out publicECDSA.pem
```

Code example

```js
const { readFileSync } = require('fs')
const fastify = require('fastify')()
const jwt = require('fastify-jwt')

fastify.register(jwt, {
  secret: {
    private: {
      key: readFileSync('path/to/publicECDSA.pem', 'utf8'),
      passphrase: 'super secret passphrase'
    },
    public: readFileSync('path/to/publicECDSA.pem', 'utf8')
  },
  sign: { algorithm: 'ES256' }
})
```
