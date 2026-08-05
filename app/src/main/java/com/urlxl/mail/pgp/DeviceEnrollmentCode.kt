package com.urlxl.mail.pgp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Crockford base32. Excludes I, L, O and U, so the user cannot mistype a code by confusing them. */
private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/** Ten characters at five bits each — the first 50 bits of the digest, MSB first. */
private const val CODE_LENGTH = 10

/**
 * The short authentication string shown during device enrollment.
 *
 * Derived from the public key in this device's own keystore — never from anything the server sent
 * back, and never from a cached copy of what was published. The browser compares its own derivation
 * (from the key the server handed it) against what the user reads off this screen; if this device
 * ever derived from a server-supplied value, the comparison would compare the server against itself
 * and the whole control would be decoration.
 *
 * [rawPublicKey] is the uncompressed SEC1 point, `0x04 ‖ X ‖ Y` with each coordinate left-padded to
 * 32 bytes — the raw 65 bytes, never their base64 text. [bucket] is `unixSeconds / 120`.
 *
 * [deviceId] is hashed as-is. It is **not** normalised, and must not be: the server bounds new ids
 * to `A-Z a-z 0-9 . _ : -`, every character of which is byte-identical under UTF-8, NFC and NFD, so
 * there is nothing to normalise. That bound exists precisely because an NFC/NFD disagreement
 * between two clients would surface to the user as a substituted key.
 */
internal fun deviceEnrollmentCode(rawPublicKey: ByteArray, deviceId: String, bucket: Long): String {
    val id = deviceId.toByteArray(Charsets.UTF_8)
    val preimage = ByteBuffer.allocate(rawPublicKey.size + 2 + id.size + 8)
        .order(ByteOrder.BIG_ENDIAN)
        .put(rawPublicKey)
        .putShort(id.size.toShort())
        .put(id)
        .putLong(bucket)
        .array()

    val digest = MessageDigest.getInstance("SHA-256").digest(preimage)

    return buildString(CODE_LENGTH) {
        for (charIndex in 0 until CODE_LENGTH) {
            var value = 0
            for (offset in 0 until 5) {
                val bit = charIndex * 5 + offset
                value = (value shl 1) or ((digest[bit / 8].toInt() shr (7 - bit % 8)) and 1)
            }
            append(CROCKFORD[value])
        }
    }
}
