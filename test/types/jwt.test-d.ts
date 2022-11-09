import fastify from 'fastify';
import fastifyJwt, { FastifyJWTOptions } from '../../jwt'
import { expectAssignable } from 'tsd'

const app = fastify();

const secretOptions = {
  secret: 'supersecret',
  publicPrivateKey: {
    public: 'publicKey',
    private: 'privateKey'
  },
  secretFnCallback: (_req, _token, cb) => { cb(null, 'supersecret') },
  secretFnPromise: (_req, _token) => Promise.resolve('supersecret'),
  secretFnAsync: async (_req, _token) => 'supersecret',
  secretFnBufferCallback: (_req, _token, cb) => { cb(null, Buffer.from('some secret', 'base64')) },
  secretFnBufferPromise: (_req, _token) => Promise.resolve(Buffer.from('some secret', 'base64')),
  secretFnBufferAsync: async (_req, _token) => Buffer.from('some secret', 'base64'),
  publicPrivateKeyFn: {
    public: (_req, _rep, cb) => { cb(null, 'publicKey') },
    private: 'privateKey'
  },
  publicPrivateKeyFn2: {
    public: 'publicKey',
    private: (_req, _rep, cb) => { cb(null, 'privateKey') },
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
  jwtDecode: true,
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
