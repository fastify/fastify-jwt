import {
  DecoderOptions,
  JwtHeader,
  KeyFetcher,
  SignerCallback,
  SignerOptions,
  VerifierCallback,
  VerifierOptions
} from 'fast-jwt'
import {
  FastifyPluginCallback,
  FastifyRequest
} from 'fastify'

declare module 'fastify' {
  interface FastifyInstance {
    jwt: fastifyJwt.JWT
  }

  interface FastifyReply {
    jwtSign(payload: fastifyJwt.SignPayloadType, options?: fastifyJwt.FastifyJwtSignOptions): Promise<string>
    jwtSign(payload: fastifyJwt.SignPayloadType, callback: SignerCallback): void
    jwtSign(payload: fastifyJwt.SignPayloadType, options: fastifyJwt.FastifyJwtSignOptions, callback: SignerCallback): void
    jwtSign(payload: fastifyJwt.SignPayloadType, options?: Partial<fastifyJwt.SignOptions>): Promise<string>
    jwtSign(payload: fastifyJwt.SignPayloadType, options: Partial<fastifyJwt.SignOptions>, callback: SignerCallback): void
  }

  interface FastifyRequest {
    jwtVerify<Decoded extends fastifyJwt.VerifyPayloadType>(options?: fastifyJwt.FastifyJwtVerifyOptions): Promise<Decoded>
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    jwtVerify<Decoded extends fastifyJwt.VerifyPayloadType>(callback: VerifierCallback): void
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    jwtVerify<Decoded extends fastifyJwt.VerifyPayloadType>(options: fastifyJwt.FastifyJwtVerifyOptions, callback: VerifierCallback): void
    jwtVerify<Decoded extends fastifyJwt.VerifyPayloadType>(options?: Partial<fastifyJwt.VerifyOptions>): Promise<Decoded>
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    jwtVerify<Decoded extends fastifyJwt.VerifyPayloadType>(options: Partial<fastifyJwt.VerifyOptions>, callback: VerifierCallback): void
    jwtDecode<Decoded extends fastifyJwt.DecodePayloadType>(options?: fastifyJwt.FastifyJwtDecodeOptions): Promise<Decoded>
    jwtDecode<Decoded extends fastifyJwt.DecodePayloadType>(callback: fastifyJwt.DecodeCallback<Decoded>): void
    jwtDecode<Decoded extends fastifyJwt.DecodePayloadType>(options: fastifyJwt.FastifyJwtDecodeOptions, callback: fastifyJwt.DecodeCallback<Decoded>): void
    user: fastifyJwt.UserType
  }
}

type FastifyJwt = FastifyPluginCallback<fastifyJwt.FastifyJWTOptions>

declare namespace fastifyJwt {

  export type FastifyJwtNamespace<C extends {
    namespace?: string;
    jwtDecode?: string;
    jwtVerify?: string;
    jwtSign?: string;
  }> =
  Record<C extends { jwtDecode: string }
    ? C['jwtDecode']
    : C extends { namespace: string }
      ? `${C['namespace']}JwtDecode`
      : never,
  JWT['decode']>
  &
  Record<C extends { jwtSign: string }
    ? C['jwtSign']
    : C extends { namespace: string }
      ? `${C['namespace']}JwtSign`
      : never,
  JWT['sign']>
  &
  Record<C extends { jwtVerify: string }
    ? C['jwtVerify']
    : C extends { namespace: string }
      ? `${C['namespace']}JwtVerify`
      : never,
  JWT['verify']>

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
    | ((request: FastifyRequest, tokenOrHeader: TokenOrHeader, cb: (e: Error | null, secret: string | Buffer | undefined) => void) => void)
    | ((request: FastifyRequest, tokenOrHeader: TokenOrHeader) => Promise<string | Buffer>)

  export type VerifyPayloadType = object | string
  export type DecodePayloadType = object | string

  export interface DecodeCallback<Decoded extends DecodePayloadType> {
    (err: Error, decoded: Decoded): void
  }

  export interface SignOptions extends Omit<SignerOptions, 'expiresIn' | 'notBefore'> {
    expiresIn: number | string;
    notBefore: number | string;
    key?: string | Buffer
  }

  export interface VerifyOptions extends Omit<VerifierOptions, 'maxAge'> {
    maxAge: number | string;
    onlyCookie: boolean;
    key?: string | Buffer
  }

  export interface FastifyJWTOptions {
    secret: Secret | { public: Secret; private?: Secret }
    decode?: Partial<DecoderOptions>
    sign?: Partial<SignOptions>
    verify?: Partial<VerifyOptions> & {
      extractToken?: (request: FastifyRequest) => string | void
    }
    cookie?: {
      cookieName: string
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
      authorizationTokenUnsigned?: string
    }
    trusted?: (
      request: FastifyRequest,
      decodedToken: { [k: string]: any }
    ) => boolean | Promise<boolean> | SignPayloadType | Promise<SignPayloadType>
    formatUser?: (payload: SignPayloadType) => UserType
    jwtDecode?: string
    namespace?: string
    jwtVerify?: string
    jwtSign?: string
    decoratorName?: string
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
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    verify<Decoded extends VerifyPayloadType>(token: string, callback: VerifierCallback): void
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    verify<Decoded extends VerifyPayloadType>(token: string, options: Partial<VerifyOptions>, callback: VerifierCallback): void

    decode<Decoded extends DecodePayloadType>(token: string, options?: Partial<DecoderOptions>): null | Decoded

    lookupToken(request: FastifyRequest, options?: FastifyJWTOptions['verify']): string
  }

  export type { JwtHeader }

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

  export const fastifyJwt: FastifyJwt
  export { fastifyJwt as default }
}

declare function fastifyJwt (...params: Parameters<FastifyJwt>): ReturnType<FastifyJwt>
export = fastifyJwt
