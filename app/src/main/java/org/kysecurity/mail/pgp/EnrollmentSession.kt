package org.kysecurity.mail.pgp

import androidx.annotation.VisibleForTesting
import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * Holds the opened PGP private key for one unlock session.
 *
 * The plaintext lifetime is the real exposure, not how often BiometricPrompt appears — so it is
 * bound to the window the user already configured at "Lock after: …" rather than to a second
 * concept of its own.
 *
 * Held as a CharArray so [clear] can zero it. A String's backing array cannot be wiped, so one
 * would survive in the heap until GC and beyond, in a dump taken after the app locked.
 *
 * Registered with [ProcessState] as well, because the app lock is not the only session boundary.
 * A security wipe, `AppRestart.relaunch` and the unpair purge all reset through
 * [ProcessState.resetAll], and none of them calls `lockNow()`. Unregistered, this holder was not
 * merely missed by them — `resetAll()` reported no failure, so the wipe announced Complete with the
 * account's private key still in the heap of a process the relaunch deliberately does not kill.
 * That is the exact omission [ProcessScopedState]'s own KDoc says the registry exists to prevent.
 */
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

    /**
     * Decodes UTF-8 [plaintext] straight into the held [CharArray], without ever building a
     * `String`.
     */
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

    /**
     * Runs [block] against the held key, or returns null if none is held.
     *
     * **Scoped, and a [CharArray], because the whole point of this class is a key that can be
     * zeroed.** The accessor this replaces was `fun peek(): String? = held?.let { String(it) }` —
     * it minted a fresh, immutable, unwipeable copy of the OpenPGP private key on every call, and
     * its two callers are the read path and the send path, so ordinary use accumulated copies in
     * the heap that [clear] could not touch. The KDoc on [isHeld] named that exact hazard one line
     * above the method that committed it.
     *
     * The array handed to [block] is the live one. Do not retain it and do not mutate it; the PGP
     * entry points take `CharArray` precisely so nothing has to.
     */
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
