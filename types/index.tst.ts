import fastify from 'fastify'
import fastifyJwt, {
  FastifyJWTOptions,
  FastifyJwtNamespace,
  JwtDecodeFunction,
  JwtSignFunction,
  JwtVerifyFunction,
  JWT,
  SignOptions,
  VerifyOptions
} from '..'
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

expect<FastifyJwtNamespace<{ namespace: 'security' }>['securityJwtDecode']>().type.toBe<JwtDecodeFunction>()
expect<FastifyJwtNamespace<{ namespace: 'security' }>['securityJwtSign']>().type.toBe<JwtSignFunction>()
expect<FastifyJwtNamespace<{ namespace: 'security' }>['securityJwtVerify']>().type.toBe<JwtVerifyFunction>()

declare module 'fastify' {
  interface FastifyInstance extends FastifyJwtNamespace<{ namespace: 'tsdTest' }> {
  }
}

expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>['decode']
>().type.toBe<JwtDecodeFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>['securityJwtSign']
>().type.toBe<JwtSignFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>['securityJwtVerify']
>().type.toBe<JwtVerifyFunction>()

expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>['securityJwtDecode']
>().type.toBe<JwtDecodeFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'sign' }>['sign']
>().type.toBe<JwtSignFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>['securityJwtVerify']
>().type.toBe<JwtVerifyFunction>()

expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>['securityJwtDecode']
>().type.toBe<JwtDecodeFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>['securityJwtSign']
>().type.toBe<JwtSignFunction>()
expect<
  FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>['verify']
>().type.toBe<JwtVerifyFunction>()

expect<
  FastifyJwtNamespace<{ jwtDecode: 'decode' }>['decode']
>().type.toBe<JwtDecodeFunction>()
expect<
  FastifyJwtNamespace<{ jwtSign: 'sign' }>['sign']
>().type.toBe<JwtSignFunction>()
expect<
  FastifyJwtNamespace<{ jwtVerify: 'verify' }>['verify']
>().type.toBe<JwtVerifyFunction>()

// Verify that JWT instance methods are still distinct from request/reply
// decorator methods — the JWT instance methods take a token argument and
// are synchronous, while the request/reply decorators infer the token from
// the request and are asynchronous.
expect<JwtSignFunction>().type.not.toBe<JWT['sign']>()
expect<JwtVerifyFunction>().type.not.toBe<JWT['verify']>()
expect<JwtDecodeFunction>().type.not.toBe<JWT['decode']>()

// Issue #348: namespaced sign/verify/decode decorators on the request and
// reply objects should be callable just like the default `jwtSign`,
// `jwtVerify` and `jwtDecode` decorators.
declare module 'fastify' {
  interface FastifyInstance extends FastifyJwtNamespace<{
    namespace: 'accessToken',
    jwtDecode: 'accessTokenDecode',
    jwtSign: 'accessTokenSign',
    jwtVerify: 'accessTokenVerify'
  }> {}

  interface FastifyReply {
    accessTokenSign: JwtSignFunction
  }

  interface FastifyRequest {
    accessTokenVerify: JwtVerifyFunction
    accessTokenDecode: JwtDecodeFunction
  }
}

app.addHook('preHandler', async (request, reply) => {
  // Namespaced sign on reply should accept the same overloads as jwtSign.
  expect(await reply.accessTokenSign({ user: 'userName' })).type.toBe<string>()
  expect(await reply.accessTokenSign({ user: 'userName' }, { expiresIn: '1h' })).type.toBe<string>()

  // Namespaced verify/decode on request should resolve to the decoded payload
  // without requiring a token argument.
  expect(await request.accessTokenVerify()).type.toBe<object | string>()
  expect(await request.accessTokenVerify<{ user: string }>()).type.toBe<{ user: string }>()
  expect(await request.accessTokenDecode()).type.toBe<object | string>()
  expect(await request.accessTokenDecode<{ user: string }>()).type.toBe<{ user: string }>()
})

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
