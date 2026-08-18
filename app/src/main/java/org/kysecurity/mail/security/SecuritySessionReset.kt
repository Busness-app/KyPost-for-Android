package org.kysecurity.mail.security

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/**
 * Runs a destructive security change and the session reset that completes it as **one**
 * non-cancellable unit.
 *
 * Splitting the two is a silent correctness hole that reads as obviously fine:
 *
 * ```
 * lifecycleScope.launch {
 *     withContext(SecurityWork) { ...destroy...; settings.setEnabled(true) }
 *     AppRestart.relaunch(this@Activity)          // <-- never runs if the Activity died
 * }
 * ```
 *
 * `NonCancellable` protects the *block*, so the destruction and the flag commit both complete. But
 * the statement after `withContext` is an ordinary cancellable continuation: it resumes through
 * `resumeCancellableWith`, sees the cancelled parent `Job`, and throws. The setting is committed and
 * the reset is skipped — leaving the outgoing session's decrypted attachment bytes, compose draft
 * and notification bookkeeping resident in a live process, under a Hostile Location Protection
 * switch reading ON.
 *
 * It depends on the dispatchers, which is what makes it easy to reason about wrongly: with the same
 * interceptor on both sides the continuation resumes undispatched and does run. `lifecycleScope` is
 * `Dispatchers.Main.immediate` and the security context is `Dispatchers.Default`, so the failing
 * case is the one that applied.
 *
 * [NonCancellable] is added here rather than taken from [workContext] so a caller cannot forget it.
 */
internal suspend fun runSecurityChangeThenReset(
    workContext: CoroutineContext,
    change: suspend () -> Unit,
    reset: suspend () -> Unit,
) = withContext(workContext + NonCancellable) {
    change()
    reset()
}
