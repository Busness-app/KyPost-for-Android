package com.urlxl.mail.push

import android.content.Context
import android.widget.Toast
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
    suspend fun respond(context: Context, challengeId: String, approve: Boolean) {
        val appContext = context.applicationContext
        PushNotificationDispatcher.cancelMfaChallenge(appContext, challengeId)
        // Answered once, answerable once: a replayed notification tap must not re-open a decision
        // the user already made.
        MfaChallengeTracker(appContext).clear(challengeId)

        val graph = PushRuntime.graph(appContext)
        val pairing = graph.repository.pairingForAuthenticatedCall()
        if (pairing == null) {
            showResultToast(appContext, "Not paired with a server")
            return
        }

        when (val result = graph.mfaResponseClient.respond(pairing, challengeId, approve)) {
            is MfaRespondResult.Success -> showResultToast(
                appContext,
                if (approve) "Sign-in approved" else "Sign-in denied",
            )
            is MfaRespondResult.Error -> showResultToast(appContext, result.message)
        }
    }

    private suspend fun showResultToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }
}
