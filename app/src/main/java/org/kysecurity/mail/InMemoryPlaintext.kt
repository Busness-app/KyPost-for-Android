package org.kysecurity.mail

/**
 * Destroys every process-scoped holder of message plaintext and account-scoped state.
 *
 * Process-scoped `object`s are not self-expiring: [org.kysecurity.mail.security.AppRestart.relaunch]
 * does not kill the process, so without this a security wipe would run to completion, remove the app
 * lock, relaunch into the same JVM and leave the victim's unsent message one tap away in a session
 * the attacker now controls. The same statics also crossed an unpair/re-pair, restoring one
 * account's draft inside another account's session.
 *
 * **Deliberately does not enumerate the holders.** A hand-maintained list went stale the first time
 * one was added — see [ProcessScopedState], which holders now register with instead.
 *
 * **Not called from `AppLockManager.lockNow()`:** the draft cache exists precisely so a
 * lock-interrupted composition survives, and clearing it there would discard the user's message on
 * every ordinary lock.
 */
object InMemoryPlaintext {
    /** Returns the names of holders that failed to clear, so a caller that must report honestly
     *  ([org.kysecurity.mail.security.SecurityWipe]) can refuse to claim a clean wipe. Empty on success. */
    fun clearAll(): List<String> = ProcessState.resetAll()
}
