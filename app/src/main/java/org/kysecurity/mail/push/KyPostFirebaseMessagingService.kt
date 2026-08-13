package org.kysecurity.mail.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.kysecurity.mail.security.SecurityWipe

private const val TAG = "KyPostFcm"

class KyPostFirebaseMessagingService : FirebaseMessagingService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        PushNotificationDispatcher.ensureChannel(this)
        PushNotificationDispatcher.ensureMfaChannel(this)
    }

    override fun onNewToken(token: String) {
        // Guarded for a sharper reason than the receive path: this re-registers with the relay,
        // and every successful registration MINTS A NEW DEVICE SECRET. A token refresh would
        // hand a freshly valid credential to a device whose wipe failed, re-arming the very
        // access the wipe was trying to revoke.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Refusing to re-register: a previous wipe was abandoned")
            return
        }
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.syncCoordinator.syncProvidedToken(token)
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // Before the payload is even parsed. A wipe that gave up leaves the pairing credential on
        // disk more often than not, so the relay keeps pushing and this service would keep
        // rendering sender and subject onto the lock screen of a device the app already tried to
        // erase itself from — and would keep offering MFA approvals on it. Drop everything.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Dropping push: a previous wipe was abandoned with data still on this device")
            return
        }

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

