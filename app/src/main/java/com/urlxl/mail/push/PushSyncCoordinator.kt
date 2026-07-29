package com.urlxl.mail.push

import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.tasks.await

/**
 * Every registration this class performs mints a **new** `deviceSecret` server-side and invalidates
 * the previous one (see [NativeRegistrationResponse.deviceSecret]). That makes registering while
 * the result cannot be stored strictly destructive: the working credential is revoked and its
 * replacement is discarded. [PushRepository.currentCredentialState] is therefore a precondition on
 * every path below, not a courtesy check — with the credential PIN gate on, a background FCM token
 * rotation in a process that was never PIN-unlocked used to leave the device permanently
 * unauthenticated behind a UI still reading "Paired".
 */
class PushSyncCoordinator(
    private val repository: PushRepository,
    private val registrationClient: NativeRegistrationClient,
) {
    /** The error every deferred registration reports, so the pairing screen shows one explanation
     *  rather than a transport-specific one per entry point. */
    private fun credentialGateDeferral() = NativeRegistrationResult.Error(
        "Unlock with your PIN to sync push registration",
    )

    suspend fun attemptPairing(pairing: PairingData): NativeRegistrationResult {
        // Taken BEFORE the network call and reused after it: the app can lock while the call is in
        // flight, and re-reading the state on the way out would discard a secret the server has
        // already committed to.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) return credentialGateDeferral()

        val token = fetchFcmTokenOrNull()
            ?: return NativeRegistrationResult.Error("Unable to fetch FCM token")

        val result = registrationClient.register(pairing = pairing, token = token)
        if (result is NativeRegistrationResult.Success) {
            repository.savePairing(
                pairing.copy(deviceId = result.deviceId ?: pairing.deviceId, deviceSecret = result.deviceSecret),
                credentialState,
            )
            // TOFU: capture the TLS pin only here, on the pairing call itself — never on the
            // routine resyncs below (syncAndPersist), so a MITM that appears after pairing gets
            // rejected rather than silently re-trusted on the next successful resync.
            result.tlsPin?.let { repository.saveTlsPin(it) }
            persistDelivery(pairing, result)
            repository.updateTransport(result.transport)
            repository.updateSyncState(lastSyncAtEpochMs = result.syncedAtEpochMs, syncError = null)
        }
        return result
    }

    suspend fun syncCurrentPairingToken(): NativeRegistrationResult {
        val state = repository.state.first()
        val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")

        val token = fetchFcmTokenOrNull()
            ?: run {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = "Unable to fetch FCM token")
                return NativeRegistrationResult.Error("Unable to fetch FCM token")
            }

        return syncAndPersist(pairing = pairing, token = token)
    }

    suspend fun syncProvidedToken(
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        val state = repository.state.first()
        val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")
        return syncAndPersist(pairing = pairing, token = token, transport = transport, p256dh = p256dh, auth = auth)
    }

    /**
     * Resyncs using whichever transport is currently confirmed active, instead of always
     * assuming FCM: if the last successful registration was unifiedpush, resends the stored
     * endpoint + WebPush keys (there's no way to re-fetch these from the connector on demand,
     * they only arrive via onNewEndpoint), otherwise falls back to [syncCurrentPairingToken].
     * Used by user/app-initiated resyncs (e.g. "resync token", app-open) — NOT by flows that
     * explicitly want to force FCM (switching away from UnifiedPush), which should keep calling
     * [syncCurrentPairingToken] directly.
     */
    suspend fun resyncActiveTransport(): NativeRegistrationResult {
        val state = repository.state.first()
        val endpoint = state.unifiedPushEndpoint
        // unifiedPushEndpoint is only ever set (see syncAndPersist) when we last successfully
        // registered with transport="unifiedpush", and cleared on any other successful sync —
        // it's a reliable local signal independent of whether the server echoes transport back.
        return if (endpoint != null) {
            val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")
            syncAndPersist(
                pairing = pairing,
                token = endpoint,
                transport = PushTransport.UNIFIED_PUSH,
                p256dh = state.unifiedPushP256dh,
                auth = state.unifiedPushAuth,
            )
        } else {
            syncCurrentPairingToken()
        }
    }

    private suspend fun syncAndPersist(
        pairing: PairingData,
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        // The single choke point for every resync entry point (token refresh, transport switch,
        // manual "Resync token", app-open recovery), so none of them can register into a state
        // where the minted secret has nowhere to go. Reported as a sync error like any other, which
        // is what surfaces it on the pairing screen instead of failing silently in the background.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) {
            val deferred = credentialGateDeferral()
            repository.updateSyncState(lastSyncAtEpochMs = null, syncError = deferred.message)
            return deferred
        }

        val result = registrationClient.register(
            pairing = pairing,
            token = token,
            transport = transport,
            p256dh = p256dh,
            auth = auth,
        )
        when (result) {
            is NativeRegistrationResult.Success -> {
                repository.savePairing(
                    pairing.copy(deviceId = result.deviceId ?: pairing.deviceId, deviceSecret = result.deviceSecret),
                    credentialState,
                )
                // Still TOFU — the pin is captured on the pairing call, never *replaced* here, so a
                // MITM appearing after pairing is still rejected rather than re-trusted. But an
                // install carried over from a build that predated pinning has no pin at all and no
                // way to ever acquire one, which left it silently running the unpinned fallback
                // client forever. Capture on first success when, and only when, none is stored.
                if (repository.currentTlsPin() == null) {
                    result.tlsPin?.let { repository.saveTlsPin(it) }
                }
                persistDelivery(pairing, result)
                repository.updateTransport(result.transport)
                // Gate on the transport we requested, not result.transport: older servers may
                // not echo transport back (it's null in that case), which would otherwise wipe
                // the endpoint/keys we just successfully registered right after setting them.
                if (transport == PushTransport.UNIFIED_PUSH) {
                    repository.updateUnifiedPushRegistration(endpoint = token, p256dh = p256dh, auth = auth)
                } else {
                    repository.updateUnifiedPushRegistration(endpoint = null, p256dh = null, auth = null)
                }
                repository.updateSyncState(lastSyncAtEpochMs = result.syncedAtEpochMs, syncError = null)
            }
            is NativeRegistrationResult.Error -> repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
        }
        return result
    }

    private suspend fun persistDelivery(pairing: PairingData, result: NativeRegistrationResult.Success) {
        val endpoint = resolvePullEndpoint(pairing.serverUrl, result.pullEndpoint)
        repository.updateDelivery(result.deliveryMode, endpoint)
    }

    private suspend fun fetchFcmTokenOrNull(): String? {
        return runCatching { FirebaseMessaging.getInstance().token.await() }.getOrNull()
    }
}
