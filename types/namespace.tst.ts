import fastify from 'fastify'
import fastifyJwt, { JWT } from '..'
import { expect } from 'tstyche'

// declare the registered namespaces so `fastify.jwt` is typed
// as the namespace -> JWT map created at runtime
declare module '..' {
  interface FastifyJWT {
    namespaces: 'auth' | 'admin'
  }
}

const app = fastify()

app.register(fastifyJwt, { secret: 'auth-secret', namespace: 'auth' })
app.register(fastifyJwt, { secret: 'admin-secret', namespace: 'admin' })

expect(app.jwt).type.toBe<Record<'auth' | 'admin', JWT>>()
expect(app.jwt.auth).type.toBe<JWT>()
expect(app.jwt.admin).type.toBe<JWT>()
expect(app.jwt.auth.sign).type.toBe<JWT['sign']>()
expect(app.jwt.admin.verify).type.toBe<JWT['verify']>()
expect(app.jwt.admin.decode).type.toBe<JWT['decode']>()

// the single-decorator shape must not leak into namespace mode
expect(app.jwt).type.not.toHaveProperty('sign')
expect(app.jwt).type.not.toHaveProperty('verify')
expect(app.jwt).type.not.toHaveProperty('decode')

// only declared namespaces are available
expect(app.jwt).type.not.toHaveProperty('other')
