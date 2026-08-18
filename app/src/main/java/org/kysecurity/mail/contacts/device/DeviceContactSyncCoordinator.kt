package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean

class DeviceContactSyncCoordinator(
    private val repository: DeviceContactRepository,
    private val settings: DeviceContactSyncSettings,
    /**
     * Hostile Location Protection makes Room in-memory so nothing reaches disk — but device
     * contact sync writes names, email addresses, phone numbers and PGP keys into the OS contacts
     * provider, which is not this app's storage and is not in-memory. Syncing while protection is
     * on published exactly the data the feature exists to withhold, so it is refused outright
     * rather than merely defaulted off.
     */
    private val hostileLocationEnabled: () -> Boolean = { false },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var debounceJob: kotlinx.coroutines.Job? = null
    private val isSyncing = AtomicBoolean(false)

    private fun syncAllowed(): Boolean = settings.isEnabled() && !hostileLocationEnabled()

    fun syncNowAsync() {
        if (!syncAllowed() || isSyncing.getAndSet(true)) return
        scope.launch { runBoundedSync("syncNow") }
    }

    fun syncWithDebounce() {
        if (!syncAllowed()) return
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(3000)
            if (!isSyncing.getAndSet(true)) runBoundedSync("debounced")
        }
    }

    /**
     * One sync cycle under the 30-second ceiling, releasing [isSyncing] however it ends.
     *
     * Deliberately not `runCatching`, which catches **`Throwable`** and so would swallow the
     * `TimeoutCancellationException` that `withTimeoutOrNull` aborts with — eating the cancellation
     * of the very timeout that bounds it.
     */
    private suspend fun runBoundedSync(trigger: String) {
        try {
            val failedStages = withTimeoutOrNull(SYNC_TIMEOUT_MS) {
                try {
                    repository.syncAll()
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    android.util.Log.e(TAG, "Sync ($trigger) threw before any stage could report", e)
                    listOf("syncAll")
                }
            }
            when {
                failedStages == null ->
                    android.util.Log.e(TAG, "Sync ($trigger) hit the ${SYNC_TIMEOUT_MS}ms ceiling and was abandoned")
                failedStages.isNotEmpty() ->
                    android.util.Log.e(TAG, "Sync ($trigger) stages failed: $failedStages")
            }
        } finally {
            isSyncing.set(false)
        }
    }

    private companion object {
        const val TAG = "DeviceContactSync"
        const val SYNC_TIMEOUT_MS = 30_000L
    }
}
