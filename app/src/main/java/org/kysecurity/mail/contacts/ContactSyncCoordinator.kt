package org.kysecurity.mail.contacts

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class ContactSyncCoordinator(
    private val repository: ContactSyncRepository,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun syncNowAsync() {
        // Not runCatching: it catches Throwable, so a cancellation became a silent success and a
        // migration or serialization bug left the user staring at stale contacts with empty logs.
        scope.launch {
            try {
                val outcome = repository.sync()
                if (outcome !is ContactSyncOutcome.Success) {
                    android.util.Log.w(TAG, "Contact sync did not complete: $outcome")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Contact sync threw", e)
            }
        }
    }

    private companion object {
        const val TAG = "ContactSync"
    }
}
