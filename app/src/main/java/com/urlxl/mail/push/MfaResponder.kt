package com.urlxl.mail.push

import android.content.Context
import android.widget.Toast
import com.urlxl.mail.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Sends the user's approve/deny decision for an MFA challenge.
 *
 * This used to be a companion object on a `BroadcastReceiver` wired to "Approve"/"Deny" actions on
 * the notification itself. Those actions are gone (see
 * [PushNotificationDispatcher.showMfaChallenge]), and with them the receiver: the only caller now
 * is [MfaApprovalActivity], which re-authenticates the user first. Keeping this as a plain object
 * means there is no exported-or-not surface to reason about at all.
 */
object MfaResponder {
    /**
     * Returns true when the decision actually reached the server.
     *
     * The notification is cancelled and the tracker cleared only on success. Doing both up front —
     * as this used to — meant a network failure left the user with a toast and no way back: the
     * notification was gone, and [MfaChallengeTracker.isPending] now rejected the id, so
     * [MfaApprovalActivity.adoptChallenge] would finish immediately on any later attempt. The
     * sign-in they meant to approve then timed out with "Network error" as the only explanation.
     *
     * Cancel-on-success still preserves the replay property that ordering was there for: a
     * decision that reached the server cannot be re-opened.
     */
    /**
     * [decisionKeys] are the credential keys the calling screen derived when it verified the PIN for
     * *this* decision, or null when the credential gate is off (in which case the stored secret needs
     * no key). They are passed in rather than read back through
     * [com.urlxl.mail.security.AppLockManager.cachedCredentialKeys] because this runs while the app
     * is still locked — a notification tap does not unlock the app — and that accessor deliberately
     * returns null in exactly that state, which made every gated approve and deny unsendable.
     */
    suspend fun respond(
        context: Context,
        payload: MfaChallengePayload,
        approve: Boolean,
        matchDigits: String = "",
        decisionKeys: com.urlxl.mail.security.CredentialKeys? = null,
    ): Boolean {
        val appContext = context.applicationContext
        val challengeId = payload.challengeId

        val graph = PushRuntime.graph(appContext)
        val pairing = if (decisionKeys != null) {
            graph.repository.pairingForAuthenticatedCall(decisionKeys)
        } else {
            graph.repository.pairingForAuthenticatedCall()
        }
        if (pairing == null) {
            showResultToast(appContext, appContext.getString(R.string.mfa_respond_not_paired))
            // Nothing was sent, so the challenge is still open and the notification is still gone
            // (autoCancel removed it on tap). Same reasoning as the Error branch below.
            PushNotificationDispatcher.repostMfaChallenge(appContext, payload)
            return false
        }

        return when (val result = graph.mfaResponseClient.respond(pairing, challengeId, approve, matchDigits)) {
            is MfaRespondResult.Success -> {
                PushNotificationDispatcher.cancelMfaChallenge(appContext, challengeId)
                // Answered once, answerable once: a replayed notification tap must not re-open a
                // decision the user already made.
                graph.mfaChallengeTracker.clear(challengeId)
                showResultToast(
                    appContext,
                    appContext.getString(
                        if (approve) R.string.mfa_respond_approved else R.string.mfa_respond_denied,
                    ),
                )
                true
            }
            is MfaRespondResult.Error -> {
                // Leave the challenge answerable AND put the notification back, which this comment
                // used to claim while the code only showed a toast. `setAutoCancel(true)` removed
                // the row when the user tapped it, so without the repost their only route back is
                // the Activity they are standing on — walk away and a still-open sign-in is
                // stranded for the rest of the tracker's freshness window with no UI anywhere.
                showResultToast(
                    appContext,
                    appContext.getString(R.string.mfa_respond_failed, result.message),
                )
                PushNotificationDispatcher.repostMfaChallenge(appContext, payload)
                false
            }
        }
    }

    private suspend fun showResultToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }
}
