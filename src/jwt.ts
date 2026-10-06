import { sign, verify } from 'hono/jwt'

export async function createAccessToken(
    userId: number,
    secret: string
): Promise<string> {
    const now = Math.floor(Date.now() / 1000)

    return sign(
        {
            sub: String(userId),
            type: 'access',
            iat: now,
            exp: now + 15 * 60
        },
        secret
    )
}

export async function createRefreshToken(
    userId: number,
    secret: string,
    sessionId: string
): Promise<string> {
    const now = Math.floor(Date.now() / 1000)

    return sign(
        {
            sub: String(userId),
            type: 'refresh',
            sessionId,
            iat: now,
            exp: now + 7 * 24 * 60 * 60
        },
        secret
    )
}

export async function verifyToken(
    token: string,
    secret: string
) {
    return verify(token, secret, 'HS256')
} 