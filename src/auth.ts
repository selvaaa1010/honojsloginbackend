import { Hono } from 'hono'
import {
    createAccessToken,
    createRefreshToken,
    verifyToken
} from './jwt'
import { hashPassword, verifyPassword } from './password'
import { authMiddleware } from './middleware/authMiddleware'

type Bindings = {
    DB: D1Database
    AUTH_SESSIONS: KVNamespace
    JWT_SECRET: string
}

type Variables = {
    userId: number
    sessionId: string
}

export const auth = new Hono<{
    Bindings: Bindings
    Variables: Variables
}>()


/* =========================================================
   SIGNUP
   ========================================================= */

auth.post(
    '/signup',
    async (c) => {

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

        if (password.length < 6) {
            return c.json(
                {
                    success: false,
                    message: 'Password must be at least 6 characters'
                },
                400
            )
        }

        // Check whether user already exists
        const existingUser = await c.env.DB
            .prepare(
                `
                SELECT id
                FROM users
                WHERE email = ?
                `
            )
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

        // Hash password
        const passwordHash = await hashPassword(password)

        const now = Date.now()

        // Create user
        const result = await c.env.DB
            .prepare(
                `
                INSERT INTO users
                (
                    name,
                    email,
                    password_hash,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                `
            )
            .bind(
                name,
                email,
                passwordHash,
                now,
                now
            )
            .run()

        return c.json(
            {
                success: true,
                message: 'User registered successfully',
                userId: result.meta.last_row_id
            },
            201
        )
    }
)


/* =========================================================
   LOGIN
   ========================================================= */

auth.post(
    '/login',
    async (c) => {

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

        // Find user
        const user = await c.env.DB
            .prepare(
                `
                SELECT
                    id,
                    name,
                    email,
                    password_hash
                FROM users
                WHERE email = ?
                `
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

        // Verify password
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

        /*
         * One session ID is created for this login.
         *
         * The same sessionId is used by:
         * - access token
         * - refresh token
         * - KV session
         */
        const sessionId = crypto.randomUUID()

        // Create access token
        const accessToken = await createAccessToken(
            user.id,
            c.env.JWT_SECRET,
            sessionId
        )

        // Create refresh token
        const refreshToken = await createRefreshToken(
            user.id,
            c.env.JWT_SECRET,
            sessionId
        )

        /*
         * Store the session in KV.
         *
         * The refresh token belongs to this session.
         */
        await c.env.AUTH_SESSIONS.put(
            `session:${sessionId}`,
            JSON.stringify({
                userId: user.id,
                refreshToken,
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
    }
)


/* =========================================================
   REFRESH ACCESS TOKEN
   ========================================================= */

auth.post(
    '/refresh',
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

            // Verify refresh token
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

            // Find the session in KV
            const sessionData = await c.env.AUTH_SESSIONS.get(
                `session:${payload.sessionId}`
            )

            if (!sessionData) {
                return c.json(
                    {
                        success: false,
                        message: 'Session expired or revoked'
                    },
                    401
                )
            }

            const session = JSON.parse(sessionData) as {
                userId: number
                refreshToken: string
                createdAt: number
            }

            /*
             * Make sure the refresh token being used
             * is the refresh token belonging to this session.
             */
            if (session.refreshToken !== body.refreshToken) {
                return c.json(
                    {
                        success: false,
                        message: 'Refresh token is not valid for this session'
                    },
                    401
                )
            }

            // Create a new access token
            const accessToken = await createAccessToken(
                Number(payload.sub),
                c.env.JWT_SECRET,
                String(payload.sessionId)
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
    }
)


/* =========================================================
   LOGOUT
   ========================================================= */

auth.post(
    '/logout',
    authMiddleware,
    async (c) => {

        /*
         * We DO NOT accept refreshToken here.
         *
         * The access token is the source of truth.
         *
         * authMiddleware already verified the access token
         * and stored the sessionId in Hono context.
         */
        const sessionId = c.get('sessionId')

        // Check whether session exists
        const sessionData = await c.env.AUTH_SESSIONS.get(
            `session:${sessionId}`
        )

        if (!sessionData) {
            return c.json(
                {
                    success: false,
                    message: 'Session already expired or revoked'
                },
                401
            )
        }

        /*
         * Delete the session from KV.
         *
         * This revokes the session and its associated
         * refresh token.
         */
        await c.env.AUTH_SESSIONS.delete(
            `session:${sessionId}`
        )

        return c.json({
            success: true,
            message: 'Logged out successfully'
        })
    }
)


/* =========================================================
   FORGOT PASSWORD
   ========================================================= */

auth.post(
    '/forgot-password',
    async (c) => {

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
            .prepare(
                `
                SELECT id
                FROM users
                WHERE email = ?
                `
            )
            .bind(email)
            .first<{
                id: number
            }>()

        /*
         * We don't reveal whether the email exists.
         */
        if (!user) {
            return c.json({
                success: true,
                message: 'If the email exists, a password reset link has been generated'
            })
        }

        const resetToken = crypto.randomUUID()

        await c.env.AUTH_SESSIONS.put(
            `password-reset:${resetToken}`,
            JSON.stringify({
                userId: user.id,
                createdAt: Date.now()
            }),
            {
                expirationTtl: 15 * 60
            }
        )

        /*
         * For development/demo purposes only.
         *
         * In production this token should be sent
         * through an email service.
         */
        return c.json({
            success: true,
            message: 'Password reset token generated',
            resetToken
        })
    }
)


/* =========================================================
   RESET PASSWORD
   ========================================================= */

auth.post(
    '/reset-password',
    async (c) => {

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

        if (body.newPassword.length < 6) {
            return c.json(
                {
                    success: false,
                    message: 'Password must be at least 6 characters'
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
                401
            )
        }

        const resetSession = JSON.parse(resetData) as {
            userId: number
            createdAt: number
        }

        // Hash new password
        const passwordHash = await hashPassword(
            body.newPassword
        )

        // Update password
        await c.env.DB
            .prepare(
                `
                UPDATE users
                SET
                    password_hash = ?,
                    updated_at = ?
                WHERE id = ?
                `
            )
            .bind(
                passwordHash,
                Date.now(),
                resetSession.userId
            )
            .run()

        // Delete reset token after successful use
        await c.env.AUTH_SESSIONS.delete(
            `password-reset:${body.resetToken}`
        )

        return c.json({
            success: true,
            message: 'Password reset successfully'
        })
    }
)