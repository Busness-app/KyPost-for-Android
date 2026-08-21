package org.kysecurity.mail.push

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Drives App Pull mode; the server's `deliveryMode` is authoritative and the cursor is durable. */
class PullSyncCoordinator(
    private val repository: PushStore,
    // No default. A no-arg PullNotificationClient() built the plain unpinned client, which is the
    // same "the security control's default is off" shape the eight clients below it had.
    private val pullClient: PullNotificationClient,
    // The two Android edges, injected rather than reached through a stored Context. Without this
    // the duplicate-notification rule below could only be exercised from an instrumented test,
    // which is exactly where a concurrency bug hides.
    private val notifier: (PushPayload) -> Unit,
    private val schedule: (DeliveryMode) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** ONE pull at a time, process-wide.
     *
     *  App foreground, the pairing screen and [PullWorker] all enter [pullOnce] independently. The
     *  cursor is read at the start and advanced at the end, so two overlapping runs read the same
     *  cursor and both fetch, persist and NOTIFY the same batch. `appendPayload` dedupes history
     *  by `messageId`; the system notification manager is handed each payload regardless, so the
     *  user simply sees every message twice. */
    private val pullGate = Mutex()

    /** Fire-and-forget pull, used on app foreground and after pairing. */
    fun pullNowAsync() {
        scope.launch { runCatching { pullOnce() } }
    }

    /** Safe to call when unpaired or in push mode; reports without touching the network. */
    suspend fun pullOnce(): PullOutcome = pullGate.withLock { pullLocked() }

    private suspend fun pullLocked(): PullOutcome {
        val state = repository.state.first()
        val pairing = repository.pairingForAuthenticatedCall() ?: return PullOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return PullOutcome.NotPaired

        // Keep the periodic worker armed only while we're actually in pull mode.
        syncPeriodicSchedule(state.deliveryMode)
        if (state.deliveryMode != DeliveryMode.PULL) return PullOutcome.NotPullMode

        val endpoint = resolvePullEndpoint(pairing.serverUrl, state.pullEndpoint)
        if (endpoint.isBlank()) return PullOutcome.Failed("Server URL is not valid")
        val cursor = repository.pullCursor(pairing.subscriberId)

        return when (val result = pullClient.pull(
            pullEndpoint = endpoint,
            deviceId = deviceId,
            deviceSecret = deviceSecret,
            afterCursor = cursor,
        )) {
            is PullResult.Success -> handleSuccess(pairing.subscriberId, endpoint, cursor, result.response)
            is PullResult.Unauthorized -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Unauthorized
            }
            is PullResult.BadRequest -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Failed(result.message)
            }
            is PullResult.Retryable -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Retry(result.retryAfterSeconds)
            }
        }
    }

    private suspend fun handleSuccess(
        subscriberId: String,
        endpoint: String,
        cursor: Long,
        response: PullNotificationsResponse,
    ): PullOutcome {
        // The response mode is authoritative; persist it so a flip to push disarms polling.
        repository.updateDelivery(response.mode, endpoint)
        syncPeriodicSchedule(response.mode)

        val prepared = PullNotificationProcessor.prepare(response, currentCursor = cursor)
        for (payload in prepared.payloads) {
            // Persist to in-app history AND hand off to the system notification manager
            // BEFORE advancing the cursor, so a crash mid-batch re-fetches rather than drops.
            repository.appendPayload(payload)
            notifier(payload)
        }
        repository.advancePullCursor(subscriberId, prepared.nextCursor)
        repository.updateSyncState(lastSyncAtEpochMs = System.currentTimeMillis(), syncError = null)

        return if (response.mode == DeliveryMode.PULL) {
            PullOutcome.Pulled(prepared.payloads.size)
        } else {
            PullOutcome.NotPullMode
        }
    }

    private fun syncPeriodicSchedule(mode: DeliveryMode) = schedule(mode)
}

/** Result of a pull cycle, primarily to let [PullWorker] decide retry vs. success. */
sealed class PullOutcome {
    data class Pulled(val count: Int) : PullOutcome()
    object NotPaired : PullOutcome()
    object NotPullMode : PullOutcome()
    object Unauthorized : PullOutcome()
    data class Failed(val message: String) : PullOutcome()
    data class Retry(val retryAfterSeconds: Long?) : PullOutcome()
}
