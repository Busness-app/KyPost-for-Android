package org.kysecurity.mail.push

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * Receives UnifiedPush protocol events from whichever distributor the user picked
 * (ntfy, etc). Mirrors KyPostFirebaseMessagingService but for the UnifiedPush transport.
 * PushService is the current API; the older MessagingReceiver broadcast-based API
 * this replaced is deprecated upstream.
 */
class KyPostUnifiedPushService : PushService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val json = Json { ignoreUnknownKeys = true }

    companion object {
        private const val TAG = "KyPostUnifiedPushService"
    }

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            // pubKeySet carries the WebPush (RFC 8291) encryption keys the connector generated
            // for this endpoint. The server needs these to encrypt payloads so the connector can
            // decrypt them on receipt — without them, onMessage() only ever sees ciphertext.
            graph.syncCoordinator.syncProvidedToken(
                endpoint.url,
                transport = PushTransport.UNIFIED_PUSH,
                p256dh = endpoint.pubKeySet?.pubKey,
                auth = endpoint.pubKeySet?.auth,
            )
        }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        // Distributor rejected registration. Clear the stale distributor selection and fall
        // back to FCM so the user isn't left with no delivery at all, and surface the failure
        // through the same syncError the FCM path already renders in the pairing UI.
        UnifiedPush.removeDistributor(applicationContext)
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.repository.updateSyncState(lastSyncAtEpochMs = null, syncError = "UnifiedPush registration failed: $reason — reverted to Firebase")
            graph.syncCoordinator.syncCurrentPairingToken()
        }
    }

    override fun onUnregistered(instance: String) {
        // Explicit unregistration (user switched distributor away, or picked "none"):
        // fall back to FCM so delivery keeps working without user intervention.
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.syncCoordinator.syncCurrentPairingToken()
        }
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (!message.decrypted) {
            // The connector couldn't decrypt this message — almost always means the server
            // encrypted with a p256dh/auth key that doesn't match what we last registered
            // (or registered none at all). message.content is ciphertext, not JSON; don't
            // attempt to parse it.
            android.util.Log.w(TAG, "Dropping UnifiedPush message: decryption failed")
            return
        }

        val text = String(message.content, Charsets.UTF_8)
        val data = runCatching {
            json.decodeFromString<Map<String, String>>(text)
        }.getOrNull() ?: run {
            android.util.Log.w(TAG, "Dropping UnifiedPush message: not a valid JSON string map")
            return
        }

        // MFA challenges are excluded from UnifiedPush by design; only mail notifications
        // are expected here, but parse defensively via the same path.
        val payload = PushPayloadParser.parse(data) ?: return
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.repository.appendPayload(payload)
        }
        PushNotificationDispatcher.show(applicationContext, payload)
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }
}
