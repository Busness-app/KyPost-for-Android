package org.kysecurity.mail.push

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Every registration here mints a new `deviceSecret` and invalidates the previous one. */
class PushSyncCoordinator(
    private val repository: PushStore,
    private val registrationClient: NativeRegistrationClient,
    /** Called when an account replacement cannot prove the previous account's data is gone; see
     *  [attemptPairing]. Injected rather than called directly so the refusal is testable and so
     *  this class keeps needing no `Context`. */
    private val wipeOnIncompletePurge: suspend (List<String>) -> Unit,
    /** This build's push credential, or null when it cannot be obtained.
     *
     *  No default: it used to fall back to `FirebaseMessaging.getInstance()`, which named a
     *  library that only two of the three channels carry, from a file every channel compiles.
     *  [PushGraph] supplies the channel's own [ChannelPush], and a caller that forgets now fails
     *  to compile rather than silently registering the wrong transport. */
    private val fetchRegistrationCredential: suspend () -> PushRegistrationCredential?,
) {
    /** ONE registration at a time, process-wide.
     *
     *  Registration is triggered independently by Firebase token rotation, UnifiedPush endpoint
     *  changes, foreground resync, transport switches and the pairing screen. Each successful call
     *  invalidates the secret the previous one minted, so two in flight interleave like this:
     *  A mints secret A, B mints secret B (invalidating A), B persists B, then A's late reply
     *  persists A — and the installation is left holding a secret the server rejects, with no path
     *  back except a re-pair. `NonCancellable` never addressed this: it protects a persist from
     *  cancellation, not from a competing registration. */
    private val registrationGate = Mutex()

    /** The error every deferred registration reports, so the pairing screen shows one explanation
     *  rather than a transport-specific one per entry point. */
    private fun credentialGateDeferral() = NativeRegistrationResult.Error(
        "Unlock with your PIN to sync push registration",
    )

    suspend fun attemptPairing(pairing: PairingData): NativeRegistrationResult = registrationGate.withLock {
        // Read INSIDE the gate: a registration that finished while this one queued may have
        // changed which account is current, and so whether this is a replacement at all.
        val existing = repository.state.first().pairing
        val isReplacement = existing != null &&
            (existing.subscriberId != pairing.subscriberId || existing.serverUrl != pairing.serverUrl)

        // Taken BEFORE the network call and reused after it: the app can lock while it is in flight.
        val credentialState = repository.currentCredentialState()
        if (credentialState is PushRepository.PairingCredentialState.Unavailable) return credentialGateDeferral()

        val credential = fetchRegistrationCredential()
            ?: return NativeRegistrationResult.Error(UNAVAILABLE_CREDENTIAL)

        // NonCancellable: the server has already invalidated the previous secret by the time it answers.
        withContext(NonCancellable) {
            val result = registrationClient.register(
                pairing = pairing,
                token = credential.token,
                transport = credential.transport,
                p256dh = credential.p256dh,
                auth = credential.auth,
            )
            if (result !is NativeRegistrationResult.Success) return@withContext result

            // NOTHING is destroyed until the replacement is proven. Purging first meant a
            // replacement that failed at the FCM token fetch — offline, say — had already deleted
            // the mail, contacts, keys and pairing of the account that was working a moment ago.
            if (isReplacement) {
                val residue = repository.clearPairing()
                if (residue.isNotEmpty()) {
                    // No table carries a subscriber column, so survivors are readable by whoever
                    // pairs next. Refuse the new account and wipe rather than leave the two mixed.
                    wipeOnIncompletePurge(residue)
                    return@withContext NativeRegistrationResult.Error(
                        "Could not remove the previous account's data ($residue); erasing this device instead",
                    )
                }
            }

            persistSuccess(pairing, result, credentialState)
            // TOFU: capture the pin only on the pairing call, never on routine resyncs.
            result.tlsPin?.let { repository.saveTlsPin(it) }
            result
        }
    }

    private suspend fun persistSuccess(
        pairing: PairingData,
        result: NativeRegistrationResult.Success,
        credentialState: PushRepository.PairingCredentialState,
    ) {
        repository.savePairing(
            pairing.copy(deviceId = result.deviceId ?: pairing.deviceId, deviceSecret = result.deviceSecret),
            credentialState,
        )
        persistDelivery(pairing, result)
        repository.updateTransport(result.transport)
        repository.updateSyncState(lastSyncAtEpochMs = result.syncedAtEpochMs, syncError = null)
    }

    suspend fun syncCurrentPairingToken(): NativeRegistrationResult {
        val credential = fetchRegistrationCredential()
            ?: run {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = UNAVAILABLE_CREDENTIAL)
                return NativeRegistrationResult.Error(UNAVAILABLE_CREDENTIAL)
            }

        return syncAndPersist(
            token = credential.token,
            transport = credential.transport,
            p256dh = credential.p256dh,
            auth = credential.auth,
        )
    }

    suspend fun syncProvidedToken(
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult = syncAndPersist(token = token, transport = transport, p256dh = p256dh, auth = auth)

    /** Resyncs on the active transport; to force FCM call [syncCurrentPairingToken] directly. */
    suspend fun resyncActiveTransport(): NativeRegistrationResult {
        val state = repository.state.first()
        val endpoint = state.unifiedPushEndpoint
        // Set only after a successful unifiedpush registration, and cleared on any other sync.
        return if (endpoint != null) {
            syncAndPersist(
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
        token: String,
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult = registrationGate.withLock {
        // Read INSIDE the gate, not by the caller before it: a registration that completed while
        // this one queued replaced the deviceSecret, and re-registering with the stale one is the
        // request the server rejects.
        val rawPairing = repository.state.first().pairing
            ?: return NativeRegistrationResult.Error("Device is not paired")

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
        withContext(NonCancellable) {
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
                persistSuccess(pairing, result, credentialState)
                narrowLegacyTlsPin(result.tlsPin)
                // Gate on the transport we requested: older servers return null and would wipe what we set.
                if (transport == PushTransport.UNIFIED_PUSH) {
                    repository.updateUnifiedPushRegistration(endpoint = token, p256dh = p256dh, auth = auth)
                } else {
                    repository.updateUnifiedPushRegistration(endpoint = null, p256dh = null, auth = null)
                }
            }
            is NativeRegistrationResult.Error -> repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
        }
        return result
    }

    /** Narrows a legacy whole-chain pin set to the leaf [fresh] was observed on. Once.
     *
     *  This is NOT a renewal mechanism and there is no longer one pretending to be. Installs
     *  pinned under the old rule hold the whole chain, which admits every certificate the issuer
     *  signs; the first resync that validates against such a set replaces it with the single leaf
     *  actually presented. On an already leaf-only set there is nothing to do: the call validated
     *  because that leaf was in the chain, so the leaf it observed is the leaf already stored.
     *
     *  A renewal that mints a new key therefore breaks the pin, on purpose, and the user recovers
     *  through [PushHomeViewModel.reconnectToServer], which reopens the TOFU window and keeps the
     *  mailbox. See [org.kysecurity.mail.security.SpkiPinner.pinsForChain].
     *
     *  The host guard is not ceremony: a pin is only meaningful against the host it was observed
     *  on, and moving one silently would leave the old host unpinned. */
    private suspend fun narrowLegacyTlsPin(fresh: TlsPin?) {
        if (fresh == null) return
        if (repository.tlsPinIsLeafOnly()) return
        val stored = repository.currentTlsPin()
        if (stored != null && stored.host != fresh.host) return
        repository.saveTlsPin(fresh)
    }

    private suspend fun persistDelivery(pairing: PairingData, result: NativeRegistrationResult.Success) {
        val endpoint = resolvePullEndpoint(pairing.serverUrl, result.pullEndpoint)
        repository.updateDelivery(result.deliveryMode, endpoint)
    }

    private companion object {
        /** One message for both entry points, naming neither Firebase nor a distributor: which one
         *  is missing depends on the build, and the injected seam above is what decides. */
        const val UNAVAILABLE_CREDENTIAL = "Unable to obtain a push registration token"
    }
}
