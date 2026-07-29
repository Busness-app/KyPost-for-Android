package com.urlxl.mail

import java.util.concurrent.CopyOnWriteArrayList

/**
 * State that lives in a process-scoped `object` and must not survive into a new session.
 *
 * [com.urlxl.mail.security.AppRestart.relaunch] deliberately no longer kills the process, so
 * "process-scoped" stopped being its own expiry. Every static holder of message plaintext,
 * account-scoped state or notification bookkeeping therefore has to be reset by hand at a
 * session boundary — a security wipe, an unpair, or a re-pair.
 *
 * That obligation used to be discharged by remembering: three ad-hoc `clear()` calls scattered
 * across [com.urlxl.mail.security.SecurityWipe] and
 * [com.urlxl.mail.push.PushRepository.purgeAccountScopedData], and one holder
 * ([com.urlxl.mail.security.EphemeralAttachmentBytes], up to 64 MB of decrypted attachment
 * plaintext) that was written after those call sites and never added to them. Registration
 * inverts it: a holder announces itself, and the wipe resets whatever announced itself.
 */
interface ProcessScopedState {
    /**
     * Drop everything held for the outgoing session.
     *
     * Must be safe to call from any thread, more than once, and while another thread is reading —
     * a wipe runs concurrently with whatever the UI is doing. Must not throw; [ProcessState.resetAll]
     * isolates failures but a holder that throws is one that did not clear.
     */
    fun resetForNewSession()
}

/**
 * The registry [ProcessScopedState] holders announce themselves to.
 *
 * Holders register from their `object` initialiser, which means a holder the process has never
 * touched is never registered — and that is correct rather than a gap: an uninitialised `object`
 * holds nothing to clear. What it buys is that *touching* a holder is what enrols it, so there is
 * no path where state exists and is unregistered.
 */
object ProcessState {
    private const val TAG = "ProcessState"

    private val registered = CopyOnWriteArrayList<ProcessScopedState>()

    fun register(state: ProcessScopedState) {
        registered.addIfAbsent(state)
    }

    /**
     * Resets every registered holder, isolating failures so one bad holder cannot leave the rest
     * of the session's plaintext in memory. Returns the holders that failed, so a caller that has
     * to report honestly (see [com.urlxl.mail.security.SecurityWipe]) can.
     */
    fun resetAll(): List<String> {
        val failed = mutableListOf<String>()
        registered.forEach { state ->
            runCatching { state.resetForNewSession() }.onFailure {
                val name = state::class.java.simpleName
                failed += name
                android.util.Log.e(TAG, "Failed to reset process-scoped state: $name", it)
            }
        }
        return failed
    }
}
