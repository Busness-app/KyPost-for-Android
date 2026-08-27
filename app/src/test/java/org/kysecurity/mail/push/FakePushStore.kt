package org.kysecurity.mail.push

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.Collections

/** In-memory [PushStore] that records the ORDER of everything the coordinators do to it.
 *
 *  The bugs these tests exist for are ordering bugs — a purge before the replacement is proven, a
 *  stale registration persisting after a newer one — so the order is the assertion, not the
 *  final value. */
internal class FakePushStore(
    pairing: PairingData? = null,
    /** What [clearPairing] reports as surviving the purge. Non-empty is the failed-purge case. */
    var purgeResidue: List<String> = emptyList(),
    private var credentialState: PushRepository.PairingCredentialState =
        PushRepository.PairingCredentialState.NotGated,
) : PushStore {
    private val backing = MutableStateFlow(PushState(pairing = pairing, lastTokenSyncAtEpochMs = null, syncError = null, latestPayload = null, history = emptyList()))

    /** Synchronized: the serialization tests write to it from two threads on purpose. */
    val events: MutableList<String> = Collections.synchronizedList(mutableListOf<String>())

    var storedPin: TlsPin? = null
    var leafOnly: Boolean = true
    var cursor: Long = 0L
    val notified = mutableListOf<PushPayload>()

    /** Written by [savePairing] and dropped by [clearPairing], exactly as the real store does. */
    private var resident: ResidentAccount? = pairing?.let { ResidentAccount(it.subscriberId, it.serverUrl) }

    override val state: Flow<PushState> get() = backing

    fun currentPairing(): PairingData? = backing.value.pairing

    /** Mirrors [PushRepository.resetPairingCredential]: the credential goes, the mailbox — and so
     *  the resident marker — stays. */
    fun resetPairingCredential() {
        backing.value = backing.value.copy(pairing = null)
        storedPin = null
    }

    override fun pairingForAuthenticatedCall(): PairingData? = backing.value.pairing
    override fun residentAccount(): ResidentAccount? = resident
    override fun currentCredentialState(): PushRepository.PairingCredentialState = credentialState
    override fun currentTlsPin(): TlsPin? = storedPin
    override fun tlsPinIsLeafOnly(): Boolean = leafOnly

    override suspend fun savePairing(pairing: PairingData, credentialState: PushRepository.PairingCredentialState) {
        events += "persist:${pairing.deviceSecret}"
        backing.value = backing.value.copy(pairing = pairing)
        resident = ResidentAccount(pairing.subscriberId, pairing.serverUrl)
    }

    override suspend fun saveTlsPin(pin: TlsPin) {
        events += "savePin:${pin.host}"
        storedPin = pin
        leafOnly = true
    }

    override suspend fun clearPairing(): List<String> {
        events += "clearPairing"
        if (purgeResidue.isEmpty()) {
            backing.value = backing.value.copy(pairing = null)
            storedPin = null
            resident = null
        }
        return purgeResidue
    }

    override suspend fun updateDelivery(mode: DeliveryMode, pullEndpoint: String?) {
        backing.value = backing.value.copy(deliveryMode = mode, pullEndpoint = pullEndpoint)
    }

    override suspend fun updateTransport(transport: PushTransport?) {
        backing.value = backing.value.copy(transport = transport)
    }

    override suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?) {
        backing.value = backing.value.copy(unifiedPushEndpoint = endpoint, unifiedPushP256dh = p256dh, unifiedPushAuth = auth)
    }

    override suspend fun updateSyncState(lastSyncAtEpochMs: Long?, syncError: String?) {
        backing.value = backing.value.copy(lastTokenSyncAtEpochMs = lastSyncAtEpochMs, syncError = syncError)
    }

    override suspend fun pullCursor(subscriberId: String): Long {
        events += "readCursor:$cursor"
        return cursor
    }

    override suspend fun advancePullCursor(subscriberId: String, cursor: Long) {
        events += "advanceCursor:$cursor"
        this.cursor = maxOf(this.cursor, cursor)
    }

    override suspend fun appendPayload(payload: PushPayload) {
        events += "append:${payload.messageId}"
    }
}
