package org.kysecurity.mail.push

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Drives the "App Pull" delivery mode: fetches queued notifications directly from the
 * KyPost server (bypassing FCM / the Cloudflare relay), renders them through the
 * same [PushNotificationDispatcher] the FCM data-message path uses, and advances a
 * durable per-subscriber cursor so nothing is shown twice across polls or restarts.
 *
 * The server's `deliveryMode` (from both register and pull responses) is authoritative:
 * a single [pullOnce] both persists that mode and (dis)arms the periodic background poller.
 */
class PullSyncCoordinator(
    private val appContext: Context,
    private val repository: PushRepository,
    private val pullClient: PullNotificationClient = PullNotificationClient(),
    // Injectable so unit tests can observe rendering without an Android NotificationManager.
    private val notifier: (Context, PushPayload) -> Unit = { ctx, payload ->
        PushNotificationDispatcher.show(ctx, payload)
    },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Fire-and-forget pull, used on app foreground and after pairing. */
    fun pullNowAsync() {
        scope.launch { runCatching { pullOnce() } }
    }

    /**
     * Performs one pull cycle. Safe to call when unpaired or in push mode — it simply
     * reports [PullOutcome.NotPaired]/[PullOutcome.NotPullMode] without touching the network.
     */
    suspend fun pullOnce(): PullOutcome {
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
            notifier(appContext, payload)
        }
        repository.advancePullCursor(subscriberId, prepared.nextCursor)
        repository.updateSyncState(lastSyncAtEpochMs = System.currentTimeMillis(), syncError = null)

        return if (response.mode == DeliveryMode.PULL) {
            PullOutcome.Pulled(prepared.payloads.size)
        } else {
            PullOutcome.NotPullMode
        }
    }

    private fun syncPeriodicSchedule(mode: DeliveryMode) {
        if (mode == DeliveryMode.PULL) {
            PullScheduler.ensurePeriodic(appContext)
        } else {
            PullScheduler.cancelPeriodic(appContext)
        }
    }
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
