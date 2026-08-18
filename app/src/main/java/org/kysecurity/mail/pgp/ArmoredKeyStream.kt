package org.kysecurity.mail.pgp

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.CharBuffer
import java.util.Arrays

/**
 * A stream over an armored key held as a [CharArray], without ever building a [String].
 *
 * The OpenPGP entry points take `CharArray` so [EnrollmentSession] never has to hand out an
 * unwipeable copy of the private key. Bouncy Castle wants an [InputStream], so a byte array is
 * unavoidable — but this one is ours, and [use] zeroes it the moment the caller is done rather
 * than leaving it for the collector.
 */
internal inline fun <T> CharArray.useArmoredStream(block: (InputStream) -> T): T {
    val encoded = Charsets.UTF_8.encode(CharBuffer.wrap(this))
    val bytes = ByteArray(encoded.remaining()).also { encoded.get(it) }
    // The ByteBuffer keeps its own copy of the plaintext; zero it too.
    if (encoded.hasArray()) Arrays.fill(encoded.array(), 0)
    try {
        return block(ByteArrayInputStream(bytes))
    } finally {
        Arrays.fill(bytes, 0)
    }
}
