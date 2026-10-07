import { Hono } from 'hono'
import { authMiddleware } from './middleware/authMiddleware'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

type Variables = {
    userId: number
}

export const users = new Hono<{
    Bindings: Bindings
    Variables: Variables
}>()

users.get(
    '/me',
    authMiddleware,
    async (c) => {
        const userId = c.get('userId')

        const user = await c.env.DB
            .prepare(
                `SELECT id, name, email, created_at
         FROM users
         WHERE id = ?`
            )
            .bind(userId)
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
    }
)