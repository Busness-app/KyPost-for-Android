package com.urlxl.mail

/**
 * Message plaintext that deliberately never touches disk, and therefore has to be destroyed by
 * hand when the account goes away.
 *
 * [ComposeDraftCache] and [ForwardAttachmentHandoff] are process-scoped `object`s holding the
 * in-progress message — recipients, body and every attachment's base64 payload. Both were written
 * on the assumption that "process-scoped" is its own expiry, which was true only while
 * [com.urlxl.mail.security.AppRestart.relaunch] still killed the process. It does not any more
 * (see its own KDoc), so a security wipe would run to completion, remove the app lock, relaunch
 * into the same JVM and leave the victim's unsent message one tap away in a session the attacker
 * now controls. The same statics also crossed an unpair/re-pair, restoring one account's draft
 * inside another account's session.
 *
 * Kept as one function rather than two calls at each site so a future in-memory plaintext holder
 * has an obvious place to register, and so the behaviour is unit-testable — neither
 * [com.urlxl.mail.security.SecurityWipe] nor [com.urlxl.mail.push.PushRepository.clearPairing] can
 * be reached from a JVM test.
 *
 * Deliberately NOT called from `AppLockManager.lockNow()`: the draft cache exists precisely so a
 * lock-interrupted composition survives, and clearing it there would discard the user's message on
 * every ordinary lock.
 */
object InMemoryPlaintext {
    fun clearAll() {
        ComposeDraftCache.clear()
        ForwardAttachmentHandoff.clear()
    }
}
