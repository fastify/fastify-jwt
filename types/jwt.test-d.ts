import fastify from 'fastify';
import fastifyJwt, { FastifyJWTOptions, FastifyJwtNamespace, JWT, SignOptions, VerifyOptions } from '..'
import { expectAssignable, expectType } from 'tsd'

const app = fastify();

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
    extractToken: (request) => 'token',
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
        : payload;
    return { name: objectPayload.userName }
  },
  namespace: 'security',
  jwtVerify: 'securityVerify',
  jwtSign: 'securitySign'
}

app.register(fastifyJwt, jwtOptions);

Object.values(secretOptions).forEach((value) => {
  app.register(fastifyJwt, {...jwtOptions, secret: value });
})

app.register(fastifyJwt, {...jwtOptions, trusted: () => Promise.resolve(false || '' || Buffer.from('foo')) })

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

app.register(fastifyJwt, {...jwtOptions, decoratorName: 'token' })

// expect jwt and its subsequent methods have merged with the fastify instance
expectAssignable<object>(app.jwt)
expectAssignable<Function>(app.jwt.sign)
expectAssignable<Function>(app.jwt.verify)
expectAssignable<Function>(app.jwt.decode)
expectAssignable<Function>(app.jwt.lookupToken)
expectAssignable<FastifyJWTOptions['cookie']>(app.jwt.cookie)

app.addHook("preHandler", async (request, reply) => {
  // assert request and reply specific interface merges
  expectAssignable<Function>(request.jwtVerify)
  expectAssignable<Function>(request.jwtDecode)
  expectAssignable<object | string | Buffer>(request.user)
  expectAssignable<Function>(reply.jwtSign)

  try {
    await request.jwtVerify();
  }
  catch (err) {
    reply.send(err);
  }
});

app.post('/signup', async (req, reply) => {
  const token = app.jwt.sign({ user: "userName" });
  let data = await app.jwt.verify(token);
  const user = req.user;
  reply.send({ token });
});

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

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{namespace: 'security'}>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{namespace: 'security'}>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{namespace: 'security'}>).securityJwtVerify)

declare module 'fastify' {
  interface FastifyInstance extends FastifyJwtNamespace<{namespace: 'tsdTest'}> {
  }
}

expectType<JWT['decode']>(app.tsdTestJwtDecode)
expectType<JWT['sign']>(app.tsdTestJwtSign)
expectType<JWT['verify']>(app.tsdTestJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode'}>).decode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode'}>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtDecode: 'decode'}>).securityJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode'}>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'sign'}>).sign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtSign: 'decode'}>).securityJwtVerify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify'}>).securityJwtDecode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify'}>).securityJwtSign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ namespace: 'security', jwtVerify: 'verify'}>).verify)

expectType<JWT['decode']>(({} as FastifyJwtNamespace<{ jwtDecode: 'decode'}>).decode)
expectType<JWT['sign']>(({} as FastifyJwtNamespace<{ jwtSign: 'sign'}>).sign)
expectType<JWT['verify']>(({} as FastifyJwtNamespace<{ jwtVerify: 'verify'}>).verify)

let signOptions: SignOptions = {
  key: "supersecret",
  algorithm: "HS256",
  mutatePayload: true,
  expiresIn: 3600,
  notBefore: 0,
}

signOptions = {
  key: Buffer.from("supersecret", "utf-8"),
  algorithm: "HS256",
  mutatePayload: true,
  expiresIn: 3600,
  notBefore: 0,
}

let verifyOptions: VerifyOptions = {
  key: "supersecret",
  algorithms: ["HS256"],
  complete: true,
  cache: true,
  cacheTTL: 3600,
  maxAge: "1 hour",
  onlyCookie: false,
}

verifyOptions = {
  key: Buffer.from("supersecret", "utf-8"),
  algorithms: ["HS256"],
  complete: true,
  cache: 3600,
  cacheTTL: 3600,
  maxAge: 3600,
  onlyCookie: true,
}
