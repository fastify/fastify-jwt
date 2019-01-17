import * as fastify from "fastify";
import { IncomingMessage, Server, ServerResponse } from "http";
import { DecodeOptions, Secret, SignOptions, VerifyCallback, VerifyOptions } from "jsonwebtoken";

declare module "fastify"
{
    interface Jwt
    {
        decode: (token: string, options?: DecodeOptions) => null | { [key: string]: any } | string;
        options: {
            /**
             * decodeOptions
             */
            decode: DecodeOptions,

            /**
             * signOptions
             */
            sign: SignOptions,

            /**
             * verifyOptions
             */
            verify: VerifyOptions,
        };
        secret: Secret;
        sign: (playload: string | Buffer | object, options?: SignOptions, callback?: VerifyCallback) => string;
        verify: (token: string, options?: VerifyOptions, callback?: VerifyCallback) => Promise<object | string>;
    }
    interface FastifyInstance<HttpServer = Server, HttpRequest = IncomingMessage, HttpResponse = ServerResponse>
    {
        jwt: Jwt;
    }

    interface FastifyRequest<
        HttpRequest,
        Query = DefaultQuery,
        Params = DefaultParams,
        Headers = DefaultHeaders,
        Body = DefaultBody
        >
    {
        jwtVerify(callback?: VerifyCallback): Promise<any>;
    }
}

declare const fastifyJWT: fastify.Plugin<Server, IncomingMessage, ServerResponse, { secret: Secret }>;

export = fastifyJWT;
