package com.urlxl.mail

import android.content.Intent
import android.os.Bundle
import androidx.lifecycle.lifecycleScope
import com.urlxl.mail.push.MfaApprovalActivity
import com.urlxl.mail.push.MfaChallengePayloadParser
import com.urlxl.mail.push.MfaChallengeTracker
import com.urlxl.mail.push.PushNotificationDispatcher
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.security.LockedActivity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Launcher and router: decides between the inbox and the pairing screen, and forwards a genuine
 * MFA push to the approval screen.
 *
 * Routing moved out of `onCreate` and into [onStart] so it happens strictly after
 * [LockedActivity]'s lock check — otherwise this Activity would launch the inbox and *then*
 * redirect itself to the unlock screen, racing two Activities into the task.
 */
class MainActivity : LockedActivity() {

    private var routed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The app lock redirects and finishes in super.onCreate; nothing below may run,
        // least of all the network and database work further down this method.
        if (redirectedToUnlock) return
        routed = savedInstanceState?.getBoolean(STATE_ROUTED, false) ?: false
    }

    override fun onStart() {
        super.onStart()
        if (redirectedToUnlock) return
        // LockedActivity.onStart finishes us and shows UnlockActivity when the app is locked.
        if (isFinishing || routed) return
        routed = true
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (redirectedToUnlock) return
        setIntent(intent)
        if (isLocked()) {
            startActivity(Intent(this, com.urlxl.mail.security.UnlockActivity::class.java))
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
            val mfa = intent.extras?.let { MfaChallengePayloadParser.parse(it) }
            // MainActivity is exported as the app's launcher, so any co-installed app can start
            // it with arbitrary extras — only forward to the approval screen for a challengeId
            // that was actually delivered via a real push, not one an attacker merely supplied.
            if (mfa != null && MfaChallengeTracker(this@MainActivity).isPending(mfa.challengeId)) {
                val mfaIntent = Intent(this@MainActivity, MfaApprovalActivity::class.java)
                mfaIntent.putExtra(PushNotificationDispatcher.EXTRA_MFA_CHALLENGE_ID, mfa.challengeId)
                startActivity(mfaIntent)
                finish()
                return@launch
            }

            val configured = PushRuntime.graph(this@MainActivity).repository.state.first().pairing != null

            val targetIntent = if (configured) {
                Intent(this@MainActivity, InboxActivity::class.java).apply {
                    val msgId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID)
                    if (msgId != null) {
                        putExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID, msgId)
                        putExtra(PushNotificationDispatcher.EXTRA_SENDER, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER))
                        putExtra(PushNotificationDispatcher.EXTRA_SUBJECT, intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT))
                    }
                }
            } else {
                Intent(this@MainActivity, com.urlxl.mail.push.PushPairingActivity::class.java)
            }
            startActivity(targetIntent)
            finish()
        }
    }

    private companion object {
        const val STATE_ROUTED = "routed"
    }
}
