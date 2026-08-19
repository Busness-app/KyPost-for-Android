package org.kysecurity.mail.pgp

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.CharBuffer
import java.util.Arrays

/** Streams an armored key without building a String; zeroes the temporary bytes on exit. */
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
