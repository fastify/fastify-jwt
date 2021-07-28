import * as fastify from 'fastify'
import * as jwt from 'jsonwebtoken'

/**
 * for declaration merging
 * @example
 * ```
 * declare module 'fastify-jwt' {
 *   interface FastifyJWT {
 *     payload: { name: string; email: string }
 *   }
 * }
 * ```
 * @example
 * ```
 * // With `formatUser`.
 * declare module 'fastify-jwt' {
 *   interface FastifyJWT {
 *     payload: { Name: string; e_mail: string }
 *     user: { name: string; email: string }
 *   }
 * }
 * ```
 */
export interface FastifyJWT {
  // payload: ...
  // user: ...
}

export type SignPayloadType = FastifyJWT extends { payload: infer T }
  ? T extends string | object | Buffer
    ? T
    : string | object | Buffer
  : string | object | Buffer

export type UserType = FastifyJWT extends { user: infer T }
  ? T
  : SignPayloadType

export type TokenOrHeader = jwt.JwtHeader | { header: jwt.JwtHeader; payload: any }

export type Secret = jwt.Secret
| ((request: fastify.FastifyRequest, tokenOrHeader: TokenOrHeader, cb: (e: Error | null, secret: string | undefined) => void) => void)
| ((request: fastify.FastifyRequest, tokenOrHeader: TokenOrHeader) => Promise<string>)

export type VerifyPayloadType = object | string

export type DecodePayloadType = object | string

export interface VerifyCallback<Decoded extends VerifyPayloadType> extends jwt.VerifyCallback {
  (err: jwt.VerifyErrors, decoded: Decoded): void
}

export interface FastifyJWTOptions {
  secret: Secret | { public: Secret; private: Secret }
  decode?: jwt.DecodeOptions
  sign?: jwt.SignOptions
  verify?: jwt.VerifyOptions & { extractToken?: (request: fastify.FastifyRequest) => string | void }
  cookie?: {
    cookieName: string,
    signed: boolean
  }
  messages?: {
    badRequestErrorMessage?: string
    noAuthorizationInHeaderMessage?: string
    authorizationTokenExpiredMessage?: string
    authorizationTokenInvalid?: ((err: Error) => string) | string
    authorizationTokenUntrusted?: string
  }
  trusted?: (request: fastify.FastifyRequest, decodedToken: { [k: string]: any }) => boolean | Promise<boolean> | SignPayloadType | Promise<SignPayloadType>
  formatUser?: (payload: SignPayloadType) => UserType
}

export interface JWT {
  options: {
    decode: jwt.DecodeOptions
    sign: jwt.SignOptions
    verify: jwt.VerifyOptions
  }
  secret: jwt.Secret
  cookie?: {
    cookieName: string,
    signed: boolean
  }

  sign(payload: SignPayloadType, options?: jwt.SignOptions): string
  sign(payload: SignPayloadType, callback: jwt.SignCallback): void
  sign(payload: SignPayloadType, options: jwt.SignOptions, callback: jwt.SignCallback): void

  verify<Decoded extends VerifyPayloadType>(token: string, options?: jwt.VerifyOptions): Decoded
  verify<Decoded extends VerifyPayloadType>(token: string, callback: VerifyCallback<Decoded>): void
  verify<Decoded extends VerifyPayloadType>(token: string, options: jwt.VerifyOptions, callback: VerifyCallback<Decoded>): void

  decode<Decoded extends DecodePayloadType>(token: string, options?: jwt.DecodeOptions): null | Decoded
}

export const fastifyJWT: fastify.FastifyPluginCallback<FastifyJWTOptions>

export default fastifyJWT

declare module 'fastify' {
  interface FastifyInstance {
    jwt: JWT
  }

  interface FastifyReply {
    jwtSign(payload: SignPayloadType, options?: jwt.SignOptions): Promise<string>
    jwtSign(payload: SignPayloadType, callback: jwt.SignCallback): void
    jwtSign(payload: SignPayloadType, options: jwt.SignOptions, callback: jwt.SignCallback): void
  }

  interface FastifyRequest {
    jwtVerify<Decoded extends VerifyPayloadType>(options?: jwt.VerifyOptions): Promise<Decoded>
    jwtVerify<Decoded extends VerifyPayloadType>(callback: VerifyCallback<Decoded>): void
    jwtVerify<Decoded extends VerifyPayloadType>(options: jwt.VerifyOptions, callback: VerifyCallback<Decoded>): void
    user: UserType
  }
}
