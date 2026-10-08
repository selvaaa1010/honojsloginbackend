import { createMiddleware } from 'hono/factory'
import { verifyToken } from '../jwt'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

type Variables = {
    userId: number
    sessionId: string
}

export const authMiddleware = createMiddleware<{
    Bindings: Bindings
    Variables: Variables
}>(async (c, next) => {

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

        // Verify access token
        const payload = await verifyToken(
            token,
            c.env.JWT_SECRET
        )

        // Make sure this is an access token
        // and contains userId and sessionId
        if (
            payload.type !== 'access' ||
            !payload.sub ||
            !payload.sessionId
        ) {
            return c.json(
                {
                    success: false,
                    message: 'Invalid access token'
                },
                401
            )
        }

        // Check whether the session is still active
        const session = await c.env.AUTH_SESSIONS.get(
            `session:${payload.sessionId}`
        )

        if (!session) {
            return c.json(
                {
                    success: false,
                    message: 'Session expired or revoked'
                },
                401
            )
        }

        // Store userId and sessionId
        // so the protected route can use them
        c.set(
            'userId',
            Number(payload.sub)
        )

        c.set(
            'sessionId',
            String(payload.sessionId)
        )

        await next()

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