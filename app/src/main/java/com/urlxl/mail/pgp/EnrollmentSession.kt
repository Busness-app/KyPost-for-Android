package com.urlxl.mail.pgp

import androidx.annotation.VisibleForTesting
import com.urlxl.mail.ProcessScopedState
import com.urlxl.mail.ProcessState

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
    fun put(armoredKey: String) {
        clear()
        held = armoredKey.toCharArray()
    }

    /** True while a key is held, with no copy minted to answer it. Use this instead of
     *  `peek() != null` for a plain presence check — that would allocate an unwipeable `String`
     *  copy of the private key purely to throw it away. */
    fun isHeld(): Boolean = held != null

    fun peek(): String? = held?.let { String(it) }

    fun clear() {
        held?.fill(' ')
        held = null
    }

    @VisibleForTesting
    fun backingArrayForTest(): CharArray = held!!
}
