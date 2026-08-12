package org.kysecurity.mail

/**
 * Destroys every process-scoped holder of message plaintext and account-scoped state.
 *
 * [ComposeDraftCache] and [ForwardAttachmentHandoff] are process-scoped `object`s holding the
 * in-progress message — recipients, body and every attachment's base64 payload. Both were written
 * on the assumption that "process-scoped" is its own expiry, which was true only while
 * [org.kysecurity.mail.security.AppRestart.relaunch] still killed the process. It does not any more
 * (see its own KDoc), so a security wipe would run to completion, remove the app lock, relaunch
 * into the same JVM and leave the victim's unsent message one tap away in a session the attacker
 * now controls. The same statics also crossed an unpair/re-pair, restoring one account's draft
 * inside another account's session.
 *
 * **This no longer enumerates the holders.** It used to name two, and its own KDoc invited "a
 * future in-memory plaintext holder" to register here — after which
 * [org.kysecurity.mail.security.EphemeralAttachmentBytes] was written, parking up to 64 MB of decrypted
 * attachment plaintext in exactly this shape, and was never added. Enumeration by memory does not
 * survive contact with a growing codebase, so holders now announce themselves via
 * [ProcessScopedState] and this is a thin, honest facade over [ProcessState.resetAll].
 *
 * Deliberately NOT called from `AppLockManager.lockNow()`: the draft cache exists precisely so a
 * lock-interrupted composition survives, and clearing it there would discard the user's message on
 * every ordinary lock.
 */
object InMemoryPlaintext {
    /** Returns the names of holders that failed to clear, so a caller that must report honestly
     *  ([org.kysecurity.mail.security.SecurityWipe]) can refuse to claim a clean wipe. Empty on success. */
    fun clearAll(): List<String> = ProcessState.resetAll()
}
