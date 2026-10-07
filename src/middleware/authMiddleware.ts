import { createMiddleware } from 'hono/factory'
import { verifyToken } from '../jwt'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

type Variables = {
    userId: number
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
        const payload = await verifyToken(
            token,
            c.env.JWT_SECRET
        )

        if (
            payload.type !== 'access' ||
            !payload.sub
        ) {
            return c.json(
                {
                    success: false,
                    message: 'Invalid access token'
                },
                401
            )
        }

        c.set('userId', Number(payload.sub))

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