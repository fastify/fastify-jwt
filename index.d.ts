import * as fastify from "fastify";

import { Server, IncomingMessage, ServerResponse } from "http"

declare module "fastify"
{
    interface Jwt
    {
        sign: (data: { [key: string]: any }) => string;
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
        jwtVerify(callback?: (err, decode) => void): Promise<any>;
    }
}

declare const fastifyJWT: fastify.Plugin<Server, IncomingMessage, ServerResponse, { secret: string }>;

export = fastifyJWT;
