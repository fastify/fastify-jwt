import * as fastify from 'fastify';
import * as http from 'http';
import * as jwt from 'jsonwebtoken';

declare module 'fastify' {
  namespace JWTTypes {
    type SignPayloadType = object | string | Buffer;
    type VerifyPayloadType = object | string;
    type DecodePayloadType = object | string;

    interface SignCallback extends jwt.SignCallback {}

    interface VerifyCallback<Decoded extends VerifyPayloadType> extends jwt.VerifyCallback {
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

    sign(payload: JWTTypes.SignPayloadType, options?: jwt.SignOptions): string;
    sign(payload: JWTTypes.SignPayloadType, callback: JWTTypes.SignCallback): void;
    sign(payload: JWTTypes.SignPayloadType, options: jwt.SignOptions, callback: JWTTypes.SignCallback): void;

    verify<Decoded extends JWTTypes.VerifyPayloadType>(token: string, options?: jwt.VerifyOptions): Decoded;
    verify<Decoded extends JWTTypes.VerifyPayloadType>(token: string, callback: JWTTypes.VerifyCallback<Decoded>): void;
    verify<Decoded extends JWTTypes.VerifyPayloadType>(
      token: string,
      options: jwt.VerifyOptions,
      callback: JWTTypes.VerifyCallback<Decoded>,
    ): void;

    decode<Decoded extends JWTTypes.DecodePayloadType>(token: string, options?: jwt.DecodeOptions): null | Decoded;
  }

  interface FastifyInstance {
    jwt: JWT;
  }

  interface FastifyReply<HttpResponse> {
    jwtSign(payload: JWTTypes.SignPayloadType, options?: jwt.SignOptions): Promise<string>;
    jwtSign(payload: JWTTypes.SignPayloadType, callback: JWTTypes.SignCallback): void;
    jwtSign(payload: JWTTypes.SignPayloadType, options: jwt.SignOptions, callback: JWTTypes.SignCallback): void;
  }

  interface FastifyRequest<HttpRequest> {
    jwtVerify<Decoded extends JWTTypes.VerifyPayloadType>(options?: jwt.VerifyOptions): Promise<Decoded>;
    jwtVerify<Decoded extends JWTTypes.VerifyPayloadType>(callback: JWTTypes.VerifyCallback<Decoded>): void;
    jwtVerify<Decoded extends JWTTypes.VerifyPayloadType>(
      options: jwt.VerifyOptions,
      callback: JWTTypes.VerifyCallback<Decoded>,
    ): void;
    user: JWTTypes.SignPayloadType;
  }
}

declare interface FastifyJWTOptions {
  secret: jwt.Secret | { public: jwt.Secret; private: jwt.Secret };
  decode?: jwt.DecodeOptions;
  sign?: jwt.SignOptions;
  verify?: jwt.VerifyOptions;
  messages?: {
    badRequestErrorMessage?: string;
    noAuthorizationInHeaderMessage?: string;
    authorizationTokenExpiredMessage?: string;
    authorizationTokenInvalid?: ((err: Error) => string) | string;
    authorizationTokenUntrusted?: string;
  }
  trusted?: (request: fastify.FastifyRequest, decodedToken: {[k: string]: any}) => boolean | Promise<boolean>
}

declare const fastifyJWT: fastify.Plugin<http.Server, http.IncomingMessage, http.ServerResponse, FastifyJWTOptions>;

export = fastifyJWT;
