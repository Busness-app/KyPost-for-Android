package org.kysecurity.mail.security

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/** Reset must run inside the NonCancellable block; code after withContext resumes cancellably. */
internal suspend fun runSecurityChangeThenReset(
    workContext: CoroutineContext,
    change: suspend () -> Unit,
    reset: suspend () -> Unit,
) = withContext(workContext + NonCancellable) {
    change()
    reset()
}
