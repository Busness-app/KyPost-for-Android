package com.urlxl.mail.pgp

import androidx.annotation.VisibleForTesting

/**
 * Holds the opened PGP private key for one unlock session.
 *
 * The plaintext lifetime is the real exposure, not how often BiometricPrompt appears — so it is
 * bound to the window the user already configured at "Lock after: …" rather than to a second
 * concept of its own.
 *
 * Held as a CharArray so [clear] can zero it. A String's backing array cannot be wiped, so one
 * would survive in the heap until GC and beyond, in a dump taken after the app locked.
 */
internal object EnrollmentSession {

    @Volatile
    private var held: CharArray? = null

    /** Clears first, so replacing a key does not strand the previous one in the heap. */
    fun put(armoredKey: String) {
        clear()
        held = armoredKey.toCharArray()
    }

    fun peek(): String? = held?.let { String(it) }

    fun clear() {
        held?.fill(' ')
        held = null
    }

    @VisibleForTesting
    fun backingArrayForTest(): CharArray = held!!
}
