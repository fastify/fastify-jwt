import * as fastify from 'fastify';
import * as http from 'http';
import * as jwt from 'jsonwebtoken';

declare module 'fastify' {
  interface JWT {
    options: {
      decode: jwt.DecodeOptions;
      sign: jwt.SignOptions;
      verify: jwt.VerifyOptions;
    };
    secret: jwt.Secret;
    sign: (payload: string | Buffer | object, options?: jwt.SignOptions, callback?: jwt.VerifyCallback) => string;
    verify: (token: string, options?: jwt.VerifyOptions, callback?: jwt.VerifyCallback) => Promise<object | string>;
    decode: (token: string, options?: jwt.DecodeOptions) => null | { [key: string]: any } | string;
  }

  interface FastifyInstance {
    jwt: JWT;
  }

  interface FastifyRequest<HttpRequest> {
    jwtVerify(callback?: jwt.VerifyCallback): Promise<any>;
  }
}

declare const fastifyJWT: fastify.Plugin<any, any, any, { secret: jwt.Secret }>;

export = fastifyJWT;
