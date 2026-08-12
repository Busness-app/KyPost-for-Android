package org.kysecurity.mail.contacts

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Mirrors push/PullSyncCoordinator.kt's fire-and-forget shape for foreground/post-edit syncs. */
class ContactSyncCoordinator(
    private val repository: ContactSyncRepository,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Fire-and-forget sync, used on app foreground and immediately after any local edit. */
    fun syncNowAsync() {
        scope.launch { runCatching { repository.sync() } }
    }
}
