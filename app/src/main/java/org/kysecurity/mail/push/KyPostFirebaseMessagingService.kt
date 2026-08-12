package org.kysecurity.mail.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class KyPostFirebaseMessagingService : FirebaseMessagingService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        PushNotificationDispatcher.ensureChannel(this)
        PushNotificationDispatcher.ensureMfaChannel(this)
    }

    override fun onNewToken(token: String) {
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.syncCoordinator.syncProvidedToken(token)
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val mfaChallenge = MfaChallengePayloadParser.parse(message.data)
        if (mfaChallenge != null) {
            PushNotificationDispatcher.showMfaChallenge(applicationContext, mfaChallenge)
            return
        }

        val payload = PushPayloadParser.parse(message.data) ?: return
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.repository.appendPayload(payload)
        }
        PushNotificationDispatcher.show(applicationContext, payload)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}

