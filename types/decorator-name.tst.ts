import fastify from 'fastify'
import fastifyJwt from '..'
import { expect } from 'tstyche'

// type the custom `decoratorName` as shown in the README:
// `FastifyRequest` lives in 'fastify', so it is augmented there,
// while `user` in `FastifyJWT` keeps typing the decoded/formatted user
interface UserPayload { id: number }
interface DecodedUser { id: number, name: string }

declare module '..' {
  interface FastifyJWT {
    payload: UserPayload
    user: DecodedUser
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    jwtUser: DecodedUser
  }
}

const app = fastify()

app.register(fastifyJwt, {
  secret: 'supersecret',
  decoratorName: 'jwtUser',
  formatUser: (payload) => {
    expect(payload).type.toBe<UserPayload>()
    return { id: payload.id, name: 'user' }
  }
})

app.get('/', async (request, reply) => {
  await request.jwtVerify()

  expect(request.jwtUser).type.toBe<DecodedUser>()
  expect(request.jwtUser.name).type.toBe<string>()

  expect(reply.jwtSign).type.toBeCallableWith({ id: 1 })
  expect(reply.jwtSign).type.not.toBeCallableWith({ id: '1' })
})

// `formatUser` must return the `user` type declared in `FastifyJWT`
expect(app.register).type.not.toBeCallableWith(fastifyJwt, {
  secret: 'supersecret',
  decoratorName: 'jwtUser',
  formatUser: (payload: UserPayload) => ({ id: payload.id })
})
