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
    suspend fun respond(
        context: Context,
        challengeId: String,
        approve: Boolean,
        matchDigits: String = "",
    ): Boolean {
        val appContext = context.applicationContext

        val graph = PushRuntime.graph(appContext)
        val pairing = graph.repository.pairingForAuthenticatedCall()
        if (pairing == null) {
            showResultToast(appContext, appContext.getString(R.string.mfa_respond_not_paired))
            return false
        }

        return when (val result = graph.mfaResponseClient.respond(pairing, challengeId, approve, matchDigits)) {
            is MfaRespondResult.Success -> {
                PushNotificationDispatcher.cancelMfaChallenge(appContext, challengeId)
                // Answered once, answerable once: a replayed notification tap must not re-open a
                // decision the user already made.
                MfaChallengeTracker(appContext).clear(challengeId)
                showResultToast(
                    appContext,
                    appContext.getString(
                        if (approve) R.string.mfa_respond_approved else R.string.mfa_respond_denied,
                    ),
                )
                true
            }
            is MfaRespondResult.Error -> {
                // Leave the challenge answerable and re-post the notification so the user has a
                // way back to it inside the tracker's freshness window.
                showResultToast(
                    appContext,
                    appContext.getString(R.string.mfa_respond_failed, result.message),
                )
                false
            }
        }
    }

    private suspend fun showResultToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }
}
