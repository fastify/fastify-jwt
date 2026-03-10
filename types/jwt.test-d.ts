import fastify from 'fastify'
import {
  expectAssignable,
  expectType
} from 'tsd'
import fastifyJwt, {
  FastifyJWTOptions,
  FastifyJwtNamespace,
  FastifyJwtPlugin,
  FastifyJwtPluginDecorators,
  JWT,
  SignOptions,
  VerifyOptions
} from '..'

const app = fastify()

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
  }
}

expectType<FastifyJwtPlugin>(fastifyJwt)

const registeredApp = fastify().register(fastifyJwt, jwtOptions)

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

expectType<FastifyJwtPluginDecorators['fastify']['jwt']>(registeredApp.jwt)
expectAssignable<Function>(registeredApp.jwt.sign)
expectAssignable<Function>(registeredApp.jwt.verify)
expectAssignable<Function>(registeredApp.jwt.decode)
expectAssignable<Function>(registeredApp.jwt.lookupToken)
expectAssignable<FastifyJWTOptions['cookie']>(registeredApp.jwt.cookie)

registeredApp.get('/verify', async (request, reply) => {
  expectType<FastifyJwtPluginDecorators['request']['jwtVerify']>(request.jwtVerify)
  expectType<FastifyJwtPluginDecorators['request']['jwtDecode']>(request.jwtDecode)
  expectAssignable<object | string | Buffer>(request.user)
  expectType<FastifyJwtPluginDecorators['reply']['jwtSign']>(reply.jwtSign)

  try {
    await request.jwtVerify()
  } catch (err) {
    reply.send(err)
  }
})

registeredApp.post('/signup', async (req, reply) => {
  const token = registeredApp.jwt.sign({ user: 'userName' })
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

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security' }>).securityJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).decode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode' }>).securityJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'sign' }>).sign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode' }>).securityJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify' }>).verify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ jwtDecode: 'decode' }>).decode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ jwtSign: 'sign' }>).sign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ jwtVerify: 'verify' }>).verify)

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
