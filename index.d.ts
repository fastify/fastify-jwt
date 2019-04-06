import * as fastify from 'fastify';
import * as http from 'http';
import * as jwt from 'jsonwebtoken';

declare module 'fastify' {
  namespace JWTTypes {
    type PayloadType = object | string;

    interface SignCallback extends jwt.SignCallback {}

    interface VerifyCallback<Decoded extends PayloadType> extends jwt.VerifyCallback {
      (err: jwt.VerifyErrors, decoded: Decoded): void;
    }
  }

  interface JWT {
    options: {
      decode: jwt.DecodeOptions;
      sign: jwt.SignOptions;
      verify: jwt.VerifyOptions;
    };
    secret: jwt.Secret;

    sign(payload: JWTTypes.PayloadType | Buffer, options?: jwt.SignOptions): string;
    sign(payload: JWTTypes.PayloadType | Buffer, callback: JWTTypes.SignCallback): void;
    sign(payload: JWTTypes.PayloadType | Buffer, options: jwt.SignOptions, callback: JWTTypes.SignCallback): void;

    verify<Decoded extends JWTTypes.PayloadType = any>(token: string, options?: jwt.VerifyOptions): Decoded;
    verify<Decoded extends JWTTypes.PayloadType = any>(token: string, callback: JWTTypes.VerifyCallback<Decoded>): void;
    verify<Decoded extends JWTTypes.PayloadType = any>(
      token: string,
      options: jwt.VerifyOptions,
      callback: JWTTypes.VerifyCallback<Decoded>,
    ): void;

    decode<Decoded extends JWTTypes.PayloadType = any>(token: string, options?: jwt.DecodeOptions): null | Decoded;
  }

  interface FastifyInstance {
    jwt: JWT;
  }

  interface FastifyReply<HttpResponse> {
    jwtSign(payload: JWTTypes.PayloadType | Buffer, options?: jwt.SignOptions): Promise<string>;
    jwtSign(payload: JWTTypes.PayloadType | Buffer, callback: JWTTypes.SignCallback): void;
    jwtSign(payload: JWTTypes.PayloadType | Buffer, options: jwt.SignOptions, callback: JWTTypes.SignCallback): void;
  }

  interface FastifyRequest<HttpRequest> {
    jwtVerify<Decoded extends JWTTypes.PayloadType = any>(options?: jwt.VerifyOptions): Promise<Decoded>;
    jwtVerify<Decoded extends JWTTypes.PayloadType = any>(callback: JWTTypes.VerifyCallback<Decoded>): void;
    jwtVerify<Decoded extends JWTTypes.PayloadType = any>(
      options: jwt.VerifyOptions,
      callback: JWTTypes.VerifyCallback<Decoded>,
    ): void;
  }
}

declare interface FastifyJWTOptions {
  secret: jwt.Secret;
  decode?: jwt.DecodeOptions;
  sign?: jwt.SignOptions;
  verify?: jwt.VerifyOptions;
}

declare const fastifyJWT: fastify.Plugin<any, any, any, FastifyJWTOptions>;

export = fastifyJWT;
