import { Hono } from 'hono'
import { createAccessToken, createRefreshToken, verifyToken } from './jwt'
import { hashPassword, verifyPassword } from './password'
import { authMiddleware } from './middleware/authMiddleware'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

export const auth = new Hono<{ Bindings: Bindings }>()

function generateId(): string {
    return crypto.randomUUID()
}

auth.post('/signup', async (c) => {
    const body = await c.req.json<{
        name: string
        email: string
        password: string
    }>()

    const name = body.name?.trim()
    const email = body.email?.trim().toLowerCase()
    const password = body.password

    if (!name || !email || !password) {
        return c.json(
            {
                success: false,
                message: 'Name, email and password are required'
            },
            400
        )
    }

    if (password.length < 8) {
        return c.json(
            {
                success: false,
                message: 'Password must contain at least 8 characters'
            },
            400
        )
    }

    const existingUser = await c.env.DB
        .prepare('SELECT id FROM users WHERE email = ?')
        .bind(email)
        .first()

    if (existingUser) {
        return c.json(
            {
                success: false,
                message: 'Email already registered'
            },
            409
        )
    }

    const passwordHash = await hashPassword(password)

    const now = Math.floor(Date.now() / 1000)

    const result = await c.env.DB
        .prepare(
            `INSERT INTO users
       (name, email, password_hash, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`
        )
        .bind(name, email, passwordHash, now, now)
        .run()

    return c.json(
        {
            success: true,
            message: 'User created successfully',
            userId: result.meta.last_row_id
        },
        201
    )
})


auth.post('/login', async (c) => {
    const body = await c.req.json<{
        email: string
        password: string
    }>()

    const email = body.email?.trim().toLowerCase()
    const password = body.password

    if (!email || !password) {
        return c.json(
            {
                success: false,
                message: 'Email and password are required'
            },
            400
        )
    }

    const user = await c.env.DB
        .prepare(
            `SELECT id, name, email, password_hash
       FROM users
       WHERE email = ?`
        )
        .bind(email)
        .first<{
            id: number
            name: string
            email: string
            password_hash: string
        }>()

    if (!user) {
        return c.json(
            {
                success: false,
                message: 'Invalid email or password'
            },
            401
        )
    }

    const passwordValid = await verifyPassword(
        password,
        user.password_hash
    )

    if (!passwordValid) {
        return c.json(
            {
                success: false,
                message: 'Invalid email or password'
            },
            401
        )
    }

    const sessionId = generateId()

    const accessToken = await createAccessToken(
        user.id,
        c.env.JWT_SECRET
    )

    const refreshToken = await createRefreshToken(
        user.id,
        c.env.JWT_SECRET,
        sessionId
    )

    await c.env.AUTH_SESSIONS.put(
        `session:${sessionId}`,
        JSON.stringify({
            userId: user.id,
            createdAt: Date.now()
        }),
        {
            expirationTtl: 7 * 24 * 60 * 60
        }
    )

    return c.json({
        success: true,
        message: 'Login successful',

        accessToken,
        refreshToken,

        user: {
            id: user.id,
            name: user.name,
            email: user.email
        }
    })
})


auth.post('/refresh', async (c) => {
    const body = await c.req.json<{
        refreshToken: string
    }>()

    if (!body.refreshToken) {
        return c.json(
            {
                success: false,
                message: 'Refresh token is required'
            },
            400
        )
    }

    try {
        const payload = await verifyToken(
            body.refreshToken,
            c.env.JWT_SECRET
        )

        if (
            payload.type !== 'refresh' ||
            !payload.sub ||
            !payload.sessionId
        ) {
            return c.json(
                {
                    success: false,
                    message: 'Invalid refresh token'
                },
                401
            )
        }

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

        const accessToken = await createAccessToken(
            Number(payload.sub),
            c.env.JWT_SECRET
        )

        return c.json({
            success: true,
            accessToken
        })

    } catch {
        return c.json(
            {
                success: false,
                message: 'Invalid or expired refresh token'
            },
            401
        )
    }
})


auth.post(
    '/logout',
    authMiddleware,
    async (c) => {
        const body = await c.req.json<{
            refreshToken: string
        }>()

        if (!body.refreshToken) {
            return c.json(
                {
                    success: false,
                    message: 'Refresh token is required'
                },
                400
            )
        }

        try {
            const accessUserId = c.get('userId')

            const payload = await verifyToken(
                body.refreshToken,
                c.env.JWT_SECRET
            )

            if (
                payload.type !== 'refresh' ||
                !payload.sub ||
                !payload.sessionId
            ) {
                return c.json(
                    {
                        success: false,
                        message: 'Invalid refresh token'
                    },
                    401
                )
            }

            const refreshUserId = Number(payload.sub)

            /*
             * Make sure the refresh token belongs
             * to the same user authenticated by
             * the access token.
             */
            if (accessUserId !== refreshUserId) {
                return c.json(
                    {
                        success: false,
                        message: 'Refresh token does not belong to the authenticated user'
                    },
                    403
                )
            }

            await c.env.AUTH_SESSIONS.delete(
                `session:${payload.sessionId}`
            )

            return c.json({
                success: true,
                message: 'Logged out successfully'
            })

        } catch {
            return c.json(
                {
                    success: false,
                    message: 'Invalid or expired refresh token'
                },
                401
            )
        }
    }
)


auth.post('/forgot-password', async (c) => {
    const body = await c.req.json<{
        email: string
    }>()

    const email = body.email?.trim().toLowerCase()

    if (!email) {
        return c.json(
            {
                success: false,
                message: 'Email is required'
            },
            400
        )
    }

    const user = await c.env.DB
        .prepare('SELECT id FROM users WHERE email = ?')
        .bind(email)
        .first<{ id: number }>()

    /*
     * Don't reveal whether an email exists.
     */
    if (!user) {
        return c.json({
            success: true,
            message:
                'If the email exists, a password reset link has been generated.'
        })
    }

    const resetToken = generateId()

    await c.env.AUTH_SESSIONS.put(
        `password-reset:${resetToken}`,
        JSON.stringify({
            userId: user.id
        }),
        {
            expirationTtl: 15 * 60
        }
    )

    /*
     * DEMO ONLY:
     * In production send this token through email.
     */
    return c.json({
        success: true,
        message: 'Password reset token generated',
        resetToken
    })
})


auth.post('/reset-password', async (c) => {
    const body = await c.req.json<{
        resetToken: string
        newPassword: string
    }>()

    if (!body.resetToken || !body.newPassword) {
        return c.json(
            {
                success: false,
                message: 'Reset token and new password are required'
            },
            400
        )
    }

    if (body.newPassword.length < 8) {
        return c.json(
            {
                success: false,
                message: 'Password must contain at least 8 characters'
            },
            400
        )
    }

    const resetData = await c.env.AUTH_SESSIONS.get(
        `password-reset:${body.resetToken}`
    )

    if (!resetData) {
        return c.json(
            {
                success: false,
                message: 'Invalid or expired reset token'
            },
            400
        )
    }

    const { userId } = JSON.parse(resetData)

    const passwordHash = await hashPassword(
        body.newPassword
    )

    await c.env.DB
        .prepare(
            `UPDATE users
       SET password_hash = ?, updated_at = ?
       WHERE id = ?`
        )
        .bind(
            passwordHash,
            Math.floor(Date.now() / 1000),
            userId
        )
        .run()

    await c.env.AUTH_SESSIONS.delete(
        `password-reset:${body.resetToken}`
    )

    return c.json({
        success: true,
        message: 'Password reset successfully'
    })
})