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

/** UnifiedPush events. PushService is the current API; MessagingReceiver is deprecated. */
class KyPostUnifiedPushService : PushService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val json = Json { ignoreUnknownKeys = true }

    override fun onCreate() {
        super.onCreate()
        // PushNotificationDispatcher.show() calls ensureChannel itself, which is why mail worked
        // here without this; showMfaChallenge does not, so an MFA challenge would have posted to
        // a channel that does not exist and shown nothing. KyPostFirebaseMessagingService has
        // done both since it was written.
        PushNotificationDispatcher.ensureChannel(this)
        PushNotificationDispatcher.ensureMfaChannel(this)
    }

    companion object {
        private const val TAG = "KyPostUnifiedPushService"
    }

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        // As in KyPostFirebaseMessagingService.onNewToken: this re-registers, and registration
        // mints a new device secret. An abandoned wipe must not have its credential renewed.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Refusing to re-register: a previous wipe was abandoned")
            return
        }
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            // WebPush (RFC 8291) keys; without them onMessage only ever sees ciphertext.
            graph.syncCoordinator.syncProvidedToken(
                endpoint.url,
                transport = PushTransport.UNIFIED_PUSH,
                p256dh = endpoint.pubKeySet?.pubKey,
                auth = endpoint.pubKeySet?.auth,
            )
        }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        // Clear the stale distributor and fall back to FCM so the user isn't left with no delivery.
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
        // Same guard, same reason, as the FCM receive path: no sender or subject on the lock
        // screen of a device whose wipe could not finish.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Dropping push: a previous wipe was abandoned with data still on this device")
            return
        }

        if (!message.decrypted) {
            // content is ciphertext, not JSON — usually a p256dh/auth mismatch with what we registered.
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

        when (val incoming = IncomingPushRouter.route(data)) {
            is IncomingPush.Mfa ->
                PushNotificationDispatcher.showMfaChallenge(applicationContext, incoming.payload)
            is IncomingPush.Mail -> {
                val graph = PushRuntime.graph(applicationContext)
                serviceScope.launch { graph.repository.appendPayload(incoming.payload) }
                PushNotificationDispatcher.show(applicationContext, incoming.payload)
            }
            null -> return
        }
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }
}
