import { Hono } from 'hono'

import { auth } from './auth'
import { users } from './users'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

const app = new Hono<{
    Bindings: Bindings
}>()


/* =========================================================
   HOME
   ========================================================= */

app.get('/', (c) => {

    return c.json({
        success: true,
        message: 'Hono Authentication API is running'
    })
})


/* =========================================================
   AUTH ROUTES
   ========================================================= */

app.route('/auth', auth)


/* =========================================================
   USER ROUTES
   ========================================================= */

app.route('/users', users)


export default app