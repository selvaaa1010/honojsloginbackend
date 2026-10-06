import { Hono } from 'hono'
import { auth } from './auth'
import { users } from './users'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/', (c) => {
    return c.json({
        message: 'Hono Auth Service is running'
    })
})

app.route('/auth', auth)
app.route('/users', users)

export default app