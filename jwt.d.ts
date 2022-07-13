import {
  DecoderOptions,
  JwtHeader,
  KeyFetcher,
  SignerCallback,
  SignerOptions,
  VerifierCallback,
  VerifierOptions
} from 'fast-jwt'
import * as fastify from 'fastify'

/**
 * for declaration merging
 * @example
 * ```
 * declare module '@fastify/jwt' {
 *   interface FastifyJWT {
 *     payload: { name: string; email: string }
 *   }
 * }
 * ```
 * @example
 * ```
 * // With `formatUser`.
 * declare module '@fastify/jwt' {
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

export type TokenOrHeader = JwtHeader | { header: JwtHeader; payload: any }

export type Secret = string | Buffer | KeyFetcher | { key: Secret; passphrase: string }
| ((request: fastify.FastifyRequest, tokenOrHeader: TokenOrHeader, cb: (e: Error | null, secret: string | Buffer | undefined) => void) => void)
| ((request: fastify.FastifyRequest, tokenOrHeader: TokenOrHeader) => Promise<string | Buffer>)

export type VerifyPayloadType = object | string
export type DecodePayloadType = object | string

export interface DecodeCallback<Decoded extends DecodePayloadType> {
  (err: Error, decoded: Decoded): void
}

export interface SignOptions extends Omit<SignerOptions, "expiresIn" | "notBefore"> {
  expiresIn: number | string;
  notBefore: number | string;
}

export interface VerifyOptions extends Omit<VerifierOptions, "maxAge"> {
  maxAge: number | string;
}

export interface FastifyJWTOptions {
  secret: Secret | { public: Secret; private: Secret }
  decode?: Partial<DecoderOptions>
  sign?: Partial<SignOptions>
  verify?: Partial<VerifyOptions> & { extractToken?: (request: fastify.FastifyRequest) => string | void }
  cookie?: {
    cookieName: string,
    signed: boolean
  }
  messages?: {
    badRequestErrorMessage?: string
    badCookieRequestErrorMessage?: string
    noAuthorizationInHeaderMessage?: string
    noAuthorizationInCookieMessage?: string
    authorizationTokenExpiredMessage?: string
    authorizationTokenInvalid?: ((err: Error) => string) | string
    authorizationTokenUntrusted?: string
  }
  trusted?: (request: fastify.FastifyRequest, decodedToken: { [k: string]: any }) => boolean | Promise<boolean> | SignPayloadType | Promise<SignPayloadType>
  formatUser?: (payload: SignPayloadType) => UserType,
  jwtDecode?: boolean | string
  namespace?: string
  jwtVerify?: string
  jwtSign?: string
}

export interface JWT {
  options: {
    decode: Partial<DecoderOptions>
    sign: Partial<SignOptions>
    verify: Partial<VerifyOptions>
  }
  cookie?: {
    cookieName: string,
    signed: boolean
  }

  sign(payload: SignPayloadType, options?: Partial<SignOptions>): string
  sign(payload: SignPayloadType, callback: SignerCallback): void
  sign(payload: SignPayloadType, options: Partial<SignOptions>, callback: SignerCallback): void

  verify<Decoded extends VerifyPayloadType>(token: string, options?: Partial<VerifyOptions>): Decoded
  verify<Decoded extends VerifyPayloadType>(token: string, callback: VerifierCallback): void
  verify<Decoded extends VerifyPayloadType>(token: string, options: Partial<VerifyOptions>, callback: VerifierCallback): void

  decode<Decoded extends DecodePayloadType>(token: string, options?: Partial<DecoderOptions>): null | Decoded
}

export type { JwtHeader } from 'fast-jwt'

export const fastifyJwt: fastify.FastifyPluginCallback<FastifyJWTOptions>

export default fastifyJwt

export interface FastifyJwtSignOptions {
  sign?: Partial<SignOptions>
}

export interface FastifyJwtVerifyOptions {
  decode: Partial<DecoderOptions>
  verify: Partial<VerifyOptions>
}

export interface FastifyJwtDecodeOptions {
  decode: Partial<DecoderOptions>
  verify: Partial<VerifyOptions>
}

declare module 'fastify' {
  interface FastifyInstance {
    jwt: JWT
  }

  interface FastifyReply {
    jwtSign(payload: SignPayloadType, options?: FastifyJwtSignOptions): Promise<string>
    jwtSign(payload: SignPayloadType, callback: SignerCallback): void
    jwtSign(payload: SignPayloadType, options: FastifyJwtSignOptions, callback: SignerCallback): void
    jwtSign(payload: SignPayloadType, options?: Partial<SignOptions>): Promise<string>
    jwtSign(payload: SignPayloadType, options: Partial<SignOptions>, callback: SignerCallback): void
  }

  interface FastifyRequest {
    jwtVerify<Decoded extends VerifyPayloadType>(options?: FastifyJwtVerifyOptions): Promise<Decoded>
    jwtVerify<Decoded extends VerifyPayloadType>(callback: VerifierCallback): void
    jwtVerify<Decoded extends VerifyPayloadType>(options: FastifyJwtVerifyOptions, callback: VerifierCallback): void
    jwtVerify<Decoded extends VerifyPayloadType>(options?: Partial<VerifyOptions>): Promise<Decoded>
    jwtVerify<Decoded extends VerifyPayloadType>(options: Partial<VerifyOptions>, callback: VerifierCallback): void
    jwtDecode<Decoded extends DecodePayloadType>(options?: FastifyJwtDecodeOptions): Promise<Decoded>
    jwtDecode<Decoded extends DecodePayloadType>(callback: DecodeCallback<Decoded>): void
    jwtDecode<Decoded extends DecodePayloadType>(options: FastifyJwtDecodeOptions, callback: DecodeCallback<Decoded>): void
    user: UserType
  }
}
