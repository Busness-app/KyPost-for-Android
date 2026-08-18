package org.kysecurity.mail

import android.content.Intent
import android.os.Bundle
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.push.PushNotificationDispatcher
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.security.LockedActivity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Launcher and router: decides between the inbox and the pairing screen.
 *
 * Routing moved out of `onCreate` and into [onStart] so it happens strictly after
 * [LockedActivity]'s lock check — otherwise this Activity would launch the inbox and *then*
 * redirect itself to the unlock screen, racing two Activities into the task.
 */
class MainActivity : LockedActivity() {

    private var routed = false

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {        routed = savedInstanceState?.getBoolean(STATE_ROUTED, false) ?: false
    }

    override fun onStartUnlocked() {        // LockedActivity.onStart finishes us and shows UnlockActivity when the app is locked.
        if (isFinishing || routed) return
        routed = true
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (redirectedToUnlock) return
        setIntent(intent)
        if (isLocked()) {
            startActivity(Intent(this, org.kysecurity.mail.security.UnlockActivity::class.java))
            finish()
            return
        }
        handleIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        outState.putBoolean(STATE_ROUTED, routed)
    }

    private fun handleIntent(intent: Intent) {
        lifecycleScope.launch {
            // No MFA routing here. This used to parse `type=mfa_challenge` out of its own extras and
            // forward to the approval screen; nothing in this app ever built such an intent, because
            // the MFA notification's PendingIntent targets MfaApprovalActivity directly.
            val configured = PushRuntime.graph(this@MainActivity).repository.state.first().pairing != null

            val targetIntent = if (configured) {
                Intent(this@MainActivity, InboxActivity::class.java).apply {
                    notificationExtras(intent)?.let { putExtras(it) }
                }
            } else {
                Intent(this@MainActivity, org.kysecurity.mail.push.PushPairingActivity::class.java)
            }
            startActivity(targetIntent)
            finish()
        }
    }

    /**
     * The "open this message" extras, but only from an Intent this app actually built.
     *
     * This Activity is exported — the LAUNCHER filter requires it — so every extra on [intent] is
     * attacker-reachable by any co-installed app with no permissions at all. Forwarding them
     * unchecked let such an app drive the inbox to a message id of its choosing and put arbitrary
     * strings on screen in the position where a real sender and subject go. The token is the same
     * shape of fix as splitting `PushPairingLinkActivity` out of `PushPairingActivity`.
     */
    private fun notificationExtras(intent: Intent): Bundle? {
        val msgId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID) ?: return null
        if (!org.kysecurity.mail.push.NotificationIntentToken.matches(
                this,
                intent.getStringExtra(PushNotificationDispatcher.EXTRA_INTENT_TOKEN),
            )
        ) {
            android.util.Log.w("MainActivity", "Ignoring notification extras from an unauthenticated intent")
            return null
        }
        return Bundle().apply {
            putString(PushNotificationDispatcher.EXTRA_MESSAGE_ID, msgId)
            putString(PushNotificationDispatcher.EXTRA_SENDER, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER))
            putString(PushNotificationDispatcher.EXTRA_SUBJECT, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT))
        }
    }

    private companion object {
        const val STATE_ROUTED = "routed"
    }
}
