package org.kysecurity.mail.push

import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.tasks.await

/** Every registration here mints a new `deviceSecret` and invalidates the previous one. */
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
        // A pairing for a different account is a REPLACEMENT; purge before the call, not after.
        val existing = repository.state.first().pairing
        if (existing != null &&
            (existing.subscriberId != pairing.subscriberId || existing.serverUrl != pairing.serverUrl)
        ) {
            repository.clearPairing()
        }

        // Taken BEFORE the network call and reused after it: the app can lock while it is in flight.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) return credentialGateDeferral()

        val token = fetchFcmTokenOrNull()
            ?: return NativeRegistrationResult.Error("Unable to fetch FCM token")

        // NonCancellable: the server has already invalidated the previous secret by the time it answers.
        return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
            val result = registrationClient.register(pairing = pairing, token = token)
            if (result is NativeRegistrationResult.Success) {
                repository.savePairing(
                    pairing.copy(deviceId = result.deviceId ?: pairing.deviceId, deviceSecret = result.deviceSecret),
                    credentialState,
                )
                // TOFU: capture the pin only on the pairing call, never on routine resyncs.
                result.tlsPin?.let { repository.saveTlsPin(it) }
                persistDelivery(pairing, result)
                repository.updateTransport(result.transport)
                repository.updateSyncState(lastSyncAtEpochMs = result.syncedAtEpochMs, syncError = null)
            }
            result
        }
    }

    suspend fun syncCurrentPairingToken(): NativeRegistrationResult {
        val state = repository.state.first()
        val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")

        val token = fetchFcmTokenOrNull()
            ?: run {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = "Unable to fetch FCM token")
                return NativeRegistrationResult.Error("Unable to fetch FCM token")
            }

        return syncAndPersist(rawPairing = pairing, token = token)
    }

    suspend fun syncProvidedToken(
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        val state = repository.state.first()
        val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")
        return syncAndPersist(rawPairing = pairing, token = token, transport = transport, p256dh = p256dh, auth = auth)
    }

    /** Resyncs on the active transport; to force FCM call [syncCurrentPairingToken] directly. */
    suspend fun resyncActiveTransport(): NativeRegistrationResult {
        val state = repository.state.first()
        val endpoint = state.unifiedPushEndpoint
        // Set only after a successful unifiedpush registration, and cleared on any other sync.
        return if (endpoint != null) {
            val pairing = state.pairing ?: return NativeRegistrationResult.Error("Device is not paired")
            syncAndPersist(
                rawPairing = pairing,
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
        rawPairing: PairingData,
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        // Re-derive the registration URL every use: a stored host divergence left clients unpinned.
        val resolution = NativeRegistrationEndpointResolver.resolve(
            rawPairing.registrationUrl,
            rawPairing.serverUrl,
        )
        val pairing = when (resolution) {
            is NativeRegistrationEndpointResolver.Resolution.Resolved ->
                rawPairing.copy(registrationUrl = resolution.registrationUrl)
            NativeRegistrationEndpointResolver.Resolution.MissingServerUrl -> {
                val error = NativeRegistrationResult.Error("Stored pairing has no server URL")
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = error.message)
                return error
            }
        }

        // The single choke point for every resync, so none registers with nowhere to store the secret.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) {
            val deferred = credentialGateDeferral()
            repository.updateSyncState(lastSyncAtEpochMs = null, syncError = deferred.message)
            return deferred
        }

        // NonCancellable as in attemptPairing: the replacement secret is already minted by now.
        return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
            registerAndPersist(pairing, token, transport, p256dh, auth, credentialState)
        }
    }

    private suspend fun registerAndPersist(
        pairing: PairingData,
        token: String,
        transport: PushTransport?,
        p256dh: String?,
        auth: String?,
        credentialState: PushRepository.PairingCredentialState,
    ): NativeRegistrationResult {
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
                // Still TOFU, now with continuity. This call already validated against the stored
                // pins, so its chain is the same server and refreshing is not a downgrade — it is
                // what keeps a pin current across certificate renewals, and what upgrades installs
                // still carrying a single legacy leaf pin onto the full chain. Capturing once and
                // never again meant the stored pin went stale and bricked the pairing.
                refreshTlsPin(result.tlsPin)
                persistDelivery(pairing, result)
                repository.updateTransport(result.transport)
                // Gate on the transport we requested: older servers return null and would wipe what we set.
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

    /** Writes [fresh] when it actually differs, and only for the host already pinned.
     *
     *  The host guard is not ceremony: a pin is only meaningful against the host it was observed
     *  on, and moving one silently would leave the old host unpinned. A differing host is a
     *  re-pairing, which goes through [attemptPairing] and its unconditional capture instead. */
    private suspend fun refreshTlsPin(fresh: TlsPin?) {
        if (fresh == null) return
        val stored = repository.currentTlsPin()
        if (stored != null && stored.host != fresh.host) return
        if (stored?.spkiSha256 == fresh.spkiSha256) return
        repository.saveTlsPin(fresh)
    }

    private suspend fun persistDelivery(pairing: PairingData, result: NativeRegistrationResult.Success) {
        val endpoint = resolvePullEndpoint(pairing.serverUrl, result.pullEndpoint)
        repository.updateDelivery(result.deliveryMode, endpoint)
    }

    private suspend fun fetchFcmTokenOrNull(): String? {
        return runCatching { FirebaseMessaging.getInstance().token.await() }.getOrNull()
    }
}
