import { Hono } from 'hono'
import { verifyToken } from './jwt'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

export const users = new Hono<{ Bindings: Bindings }>()

users.get('/me', async (c) => {
    const authorization = c.req.header('Authorization')

    if (!authorization) {
        return c.json(
            {
                success: false,
                message: 'Authorization header is required'
            },
            401
        )
    }

    const [scheme, token] = authorization.split(' ')

    if (scheme !== 'Bearer' || !token) {
        return c.json(
            {
                success: false,
                message: 'Invalid authorization header'
            },
            401
        )
    }

    try {
        const payload = await verifyToken(
            token,
            c.env.JWT_SECRET
        )

        if (payload.type !== 'access' || !payload.sub) {
            return c.json(
                {
                    success: false,
                    message: 'Invalid access token'
                },
                401
            )
        }

        const user = await c.env.DB
            .prepare(
                `SELECT id, name, email, created_at
         FROM users
         WHERE id = ?`
            )
            .bind(Number(payload.sub))
            .first()

        if (!user) {
            return c.json(
                {
                    success: false,
                    message: 'User not found'
                },
                404
            )
        }

        return c.json({
            success: true,
            user
        })

    } catch {
        return c.json(
            {
                success: false,
                message: 'Invalid or expired access token'
            },
            401
        )
    }
})