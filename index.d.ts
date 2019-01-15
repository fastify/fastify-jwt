import * as http from 'http';
import * as fastify from "fastify";

declare module "fastify"
{

    interface JwtToken
    {

    }
    interface Jwt
    {
        sign: ({ playlod: any }) => JwtToken;
    }
    interface FastifyInstance<HttpServer = http.Server, HttpRequest = http.IncomingMessage, HttpResponse = http.ServerResponse>
    {
        jwt: Jwt;
    }
}
