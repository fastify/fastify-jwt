import fastify from 'fastify';
import fastifyJwt, { FastifyJWTOptions } from './jwt'
import { expectAssignable } from 'tsd'

const app = fastify();

const jwtOptions: FastifyJWTOptions = {
    secret: process.env.usePublicPrivateKeys ? "supersecret" : { public: 'publicKey', private: 'privateKey' },
    sign: {
        expiresIn: '1h'
    },
    cookie: {
        cookieName: 'jwt'
    },
    verify: {
        maxAge: '1h',
        extractToken: (request) => 'token'
    },
    decode: {
        complete: true
    },
    messages: {
        badRequestErrorMessage: 'Bad Request',
        noAuthorizationInHeaderMessage: 'No Header',
        authorizationTokenExpiredMessage: 'Token Expired',
        authorizationTokenInvalid: (err) => `${err.message}`,
        authorizationTokenUntrusted: 'Token untrusted'
    },
    trusted: () => false || '' || Buffer.from('foo')
}

app.register(fastifyJwt, jwtOptions);

app.register(fastifyJwt, {...jwtOptions, trusted: () => Promise.resolve(false || '' || Buffer.from('foo')) })

// expect jwt and its subsequent methods have merged with the fastify instance
expectAssignable<object>(app.jwt)
expectAssignable<Function>(app.jwt.sign)
expectAssignable<Function>(app.jwt.verify)
expectAssignable<Function>(app.jwt.decode)

app.addHook("preHandler", async (request, reply) => {
    // assert request and reply specific interface merges
    expectAssignable<Function>(request.jwtVerify)
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
