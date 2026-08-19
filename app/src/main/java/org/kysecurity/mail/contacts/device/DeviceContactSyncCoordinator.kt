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
    // Device sync writes into the OS contacts provider, which the in-memory database does not cover.
    private val hostileLocationEnabled: () -> Boolean = { false },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var debounceJob: kotlinx.coroutines.Job? = null
    private val isSyncing = AtomicBoolean(false)

    private fun syncAllowed(): Boolean = settings.isEnabled() && !hostileLocationEnabled()

    fun syncNowAsync() {
        if (!syncAllowed() || isSyncing.getAndSet(true)) return
        scope.launch {
            try {
                withTimeoutOrNull(30_000L) {
                    runCatching { repository.syncAll() }
                }
            } finally {
                isSyncing.set(false)
            }
        }
    }

    fun syncWithDebounce() {
        if (!syncAllowed()) return
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(3000)
            if (!isSyncing.getAndSet(true)) {
                try {
                    withTimeoutOrNull(30_000L) {
                        runCatching { repository.syncAll() }
                    }
                } finally {
                    isSyncing.set(false)
                }
            }
        }
    }
}
