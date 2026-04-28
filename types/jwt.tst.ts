import fastify from 'fastify'
import fastifyJwt, { FastifyJWTOptions, FastifyJwtNamespace, JWT, SignOptions, VerifyOptions } from './jwt'
import { expect } from 'tstyche'
import fastifyRateLimit from '@fastify/rate-limit'

const app = fastify()
app.register(fastifyRateLimit, {
  max: 100,
  timeWindow: '1 minute'
})

const secretOptions = {
  secret: 'supersecret',
  publicPrivateKey: {
    public: 'publicKey',
    private: 'privateKey'
  },
  secretFnCallback: (_req: any, _token: any, cb: any) => { cb(null, 'supersecret') },
  secretFnPromise: (_req: any, _token: any) => Promise.resolve('supersecret'),
  secretFnAsync: async (_req: any, _token: any) => 'supersecret',
  secretFnBufferCallback: (_req: any, _token: any, cb: any) => { cb(null, Buffer.from('some secret', 'base64')) },
  secretFnBufferPromise: (_req: any, _token: any) => Promise.resolve(Buffer.from('some secret', 'base64')),
  secretFnBufferAsync: async (_req: any, _token: any) => Buffer.from('some secret', 'base64'),
  publicPrivateKeyFn: {
    public: (_req: any, _rep: any, cb: any) => { cb(null, 'publicKey') },
    private: 'privateKey'
  },
  publicPrivateKeyFn2: {
    public: 'publicKey',
    private: (_req: any, _rep: any, cb: any) => { cb(null, 'privateKey') },
  }
}

const jwtOptions: FastifyJWTOptions = {
  secret: 'supersecret',
  sign: {
    expiresIn: 3600
  },
  cookie: {
    cookieName: 'jwt',
    signed: false
  },
  verify: {
    maxAge: '1 hour',
    extractToken: () => 'token',
    onlyCookie: false
  },
  decode: {
    complete: true
  },
  messages: {
    badRequestErrorMessage: 'Bad Request',
    badCookieRequestErrorMessage: 'Bad Cookie Request',
    noAuthorizationInHeaderMessage: 'No Header',
    noAuthorizationInCookieMessage: 'No Cookie',
    authorizationTokenExpiredMessage: 'Token Expired',
    authorizationTokenInvalid: (err) => `${err.message}`,
    authorizationTokenUntrusted: 'Token untrusted'
  },
  trusted: () => false || '' || Buffer.from('foo'),
  formatUser: payload => {
    const objectPayload = typeof payload === 'string'
      ? JSON.parse(payload)
      : Buffer.isBuffer(payload)
        ? JSON.parse(payload.toString())
        : payload
    return { name: objectPayload.userName }
  },
  namespace: 'security',
  jwtVerify: 'securityVerify',
  jwtSign: 'securitySign'
}

app.register(fastifyJwt, jwtOptions)

Object.values(secretOptions).forEach((value) => {
  app.register(fastifyJwt, { ...jwtOptions, secret: value })
})

app.register(fastifyJwt, { ...jwtOptions, trusted: () => Promise.resolve(false || '' || Buffer.from('foo')) })

app.register(fastifyJwt, {
  secret: {
    private: {
      key: 'privateKey',
      passphrase: 'super secret passphrase',
    },
    public: 'publicKey',
  },
  sign: { algorithm: 'ES256' },
})

app.register(fastifyJwt, { ...jwtOptions, decoratorName: 'token' })

// expect jwt and its subsequent methods have merged with the fastify instance
expect(app.jwt).type.toBeAssignableTo<object>()
expect(app.jwt.sign).type.toBeAssignableTo<Function>()
expect(app.jwt.verify).type.toBeAssignableTo<Function>()
expect(app.jwt.decode).type.toBeAssignableTo<Function>()
expect(app.jwt.lookupToken).type.toBeAssignableTo<Function>()
expect(app.jwt.cookie).type.toBeAssignableTo<FastifyJWTOptions['cookie']>()

app.addHook('preHandler', async (request, reply) => {
  // assert request and reply specific interface merges
  expect(request.jwtVerify).type.toBeAssignableTo<Function>()
  expect(request.jwtDecode).type.toBeAssignableTo<Function>()
  expect(request.user).type.toBeAssignableTo<object | string | Buffer>()
  expect(reply.jwtSign).type.toBeAssignableTo<Function>()

  try {
    await request.jwtVerify()
  } catch (err) {
    reply.code(401).send({ message: 'Unauthorized' })
  }
})

app.post('/signup', {
  preHandler: app.rateLimit(),
  config: {
    rateLimit: {
      max: 100,
      timeWindow: '1 minute'
    }
  }
}, async (req, reply) => {
  const token = app.jwt.sign({ user: 'userName' })
  reply.send({ token })
})

// define custom payload
// declare module './jwt' {
//   interface FastifyJWT {
//     payload: {
//       user: string
//     }
//   }
// }

// Custom payload with formatUser
// declare module './jwt' {
//   interface FastifyJWT {
//     payload: {
//       user: string
//     }
//     user: {
//       name: string
//     }
//   }
// }

expect(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtDecode).type.toBe<JWT['decode']>()
expect(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtSign).type.toBe<JWT['sign']>()
expect(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtVerify).type.toBe<JWT['verify']>()

declare module 'fastify' {
  interface FastifyInstance extends FastifyJwtNamespace<{ namespace: 'tsdTest' }> {
  }
}

expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).decode
).type.toBe<JWT['decode']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).securityJwtSign
).type.toBe<JWT['sign']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).securityJwtVerify
).type.toBe<JWT['verify']>()

expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>).securityJwtDecode
).type.toBe<JWT['decode']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'sign' }>).sign
).type.toBe<JWT['sign']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>).securityJwtVerify
).type.toBe<JWT['verify']>()

expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).securityJwtDecode
).type.toBe<JWT['decode']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).securityJwtSign
).type.toBe<JWT['sign']>()
expect(
  ({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).verify
).type.toBe<JWT['verify']>()

expect(
  ({} as FastifyJwtNamespace<{ jwtDecode: 'decode' }>).decode
).type.toBe<JWT['decode']>()
expect(
  ({} as FastifyJwtNamespace<{ jwtSign: 'sign' }>).sign
).type.toBe<JWT['sign']>()
expect(
  ({} as FastifyJwtNamespace<{ jwtVerify: 'verify' }>).verify
).type.toBe<JWT['verify']>()

let signOptions: SignOptions = {
  key: 'supersecret',
  algorithm: 'HS256',
  mutatePayload: true,
  expiresIn: 3600,
  notBefore: 0,
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
signOptions = {
  key: Buffer.from('supersecret', 'utf-8'),
  algorithm: 'HS256',
  mutatePayload: true,
  expiresIn: 3600,
  notBefore: 0,
}

let verifyOptions: VerifyOptions = {
  key: 'supersecret',
  algorithms: ['HS256'],
  complete: true,
  cache: true,
  cacheTTL: 3600,
  maxAge: '1 hour',
  onlyCookie: false,
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
verifyOptions = {
  key: Buffer.from('supersecret', 'utf-8'),
  algorithms: ['HS256'],
  complete: true,
  cache: 3600,
  cacheTTL: 3600,
  maxAge: 3600,
  onlyCookie: true,
}
