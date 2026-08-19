package org.kysecurity.mail.pgp

import androidx.annotation.VisibleForTesting
import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/** Holds the opened PGP private key for one unlock session, as a wipeable [CharArray]. */
internal object EnrollmentSession : ProcessScopedState {

    init { ProcessState.register(this) }

    @Volatile
    private var held: CharArray? = null

    override fun resetForNewSession() = clear()

    /** Clears first, so replacing a key does not strand the previous one in the heap. */
    fun put(armoredKey: CharArray) {
        clear()
        held = armoredKey.copyOf()
    }

    /** Decodes UTF-8 [plaintext] straight into the held [CharArray], never building a `String`. */
    fun putUtf8(plaintext: ByteArray) {
        val decoded = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(plaintext))
        val chars = CharArray(decoded.remaining()).also { decoded.get(it) }
        try {
            put(chars)
        } finally {
            java.util.Arrays.fill(chars, ' ')
            if (decoded.hasArray()) java.util.Arrays.fill(decoded.array(), ' ')
        }
    }

    /** True while a key is held, with no copy minted to answer it. Use this instead of
     *  `withKey { it != null }` for a plain presence check. */
    fun isHeld(): Boolean = held != null

    /** Runs [block] against the live held key, or null if none. Do not retain or mutate the array. */
    fun <T> withKey(block: (CharArray) -> T): T? = held?.let(block)

    /** Test-only view of the held key. Never call this from production code — see [withKey]. */
    @VisibleForTesting
    fun peekForTest(): String? = held?.let { String(it) }

    fun clear() {
        held?.fill(' ')
        held = null
    }

    @VisibleForTesting
    fun backingArrayForTest(): CharArray = held!!
}
