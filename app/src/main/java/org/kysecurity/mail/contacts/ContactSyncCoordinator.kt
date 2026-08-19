package org.kysecurity.mail.contacts

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class ContactSyncCoordinator(
    private val repository: ContactSyncRepository,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun syncNowAsync() {
        scope.launch { runCatching { repository.sync() } }
    }
}
