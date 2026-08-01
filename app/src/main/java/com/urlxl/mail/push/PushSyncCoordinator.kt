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
        // A pairing for a different account is a REPLACEMENT, and the previous account's data must
        // not survive into it. purgeAccountScopedData exists for exactly this and its own KDoc names
        // the harm — "queued contact changes were flushed to whichever server was paired next,
        // uploading one account's contacts to another" — but it was only ever reachable from the
        // explicit Unpair button and from SecurityWipe. This path, which any web page can drive
        // through the exported BROWSABLE kypost://native-pair link behind one confirmation tap,
        // called neither: the pending-change queue is not scoped by subscriber, and
        // ContactSyncRepository.sync prefers push whenever it is non-empty, so the *first* contacts
        // call to the new relay uploaded the previous account's records, pgpKey included.
        //
        // Before the network call, so a registration that succeeds cannot land on stale data.
        val existing = repository.state.first().pairing
        if (existing != null &&
            (existing.subscriberId != pairing.subscriberId || existing.serverUrl != pairing.serverUrl)
        ) {
            repository.clearPairing()
        }

        // Taken BEFORE the network call and reused after it: the app can lock while the call is in
        // flight, and re-reading the state on the way out would discard a secret the server has
        // already committed to.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) return credentialGateDeferral()

        val token = fetchFcmTokenOrNull()
            ?: return NativeRegistrationResult.Error("Unable to fetch FCM token")

        // NonCancellable from the request onward: the server mints the replacement deviceSecret and
        // invalidates the previous one before it answers, so being cancelled after the call and
        // before savePairing leaves the device holding a revoked credential behind a UI still
        // reading "Paired", recoverable only by scanning a fresh QR code. This scope belongs to the
        // pairing screen's ViewModel, which is cancelled by onCleared the moment the user navigates
        // away — a Back press during a slow registration was enough.
        return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
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
        // Re-derive the registration URL on every use rather than trusting what the store hands
        // back. NativeRegistrationEndpointResolver's own KDoc claims it "also covers a pairing
        // persisted by an older build", but its only caller runs on freshly *parsed* links — this
        // path took the stored value verbatim and put it straight into Request.Builder().url(...).
        // That URL carries the device secret and, on an install with no pin yet, is what seeds the
        // TOFU pin: OkHttp's CertificatePinner enforces nothing for a hostname it has no pattern
        // for, so a stored serverUrl/registrationUrl host divergence left every credential-bearing
        // client silently unpinned. RelayMailSource.baseUrl re-validates serverUrl per request for
        // exactly this reason.
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

        // NonCancellable for the same reason as attemptPairing: from here on the server has minted a
        // replacement secret and revoked the previous one, so dropping the response strands the
        // device with a credential that no longer works.
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
