const ITERATIONS = 100_000

function bufferToHex(buffer: ArrayBuffer): string {
    return [...new Uint8Array(buffer)]
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')
}

function hexToBuffer(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)

    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
    }

    return bytes
}

async function deriveKey(
    password: string,
    salt: Uint8Array
): Promise<ArrayBuffer> {
    const encoder = new TextEncoder()

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    )

    return crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt,
            iterations: ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    )
}

export async function hashPassword(password: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16))

    const hash = await deriveKey(password, salt)

    return `${bufferToHex(salt.buffer)}:${bufferToHex(hash)}`
}

export async function verifyPassword(
    password: string,
    storedPassword: string
): Promise<boolean> {
    const [saltHex, hashHex] = storedPassword.split(':')

    if (!saltHex || !hashHex) {
        return false
    }

    const salt = hexToBuffer(saltHex)

    const hash = await deriveKey(password, salt)

    return bufferToHex(hash) === hashHex
}