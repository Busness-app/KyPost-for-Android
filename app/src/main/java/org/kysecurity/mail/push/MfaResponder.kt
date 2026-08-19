package org.kysecurity.mail.push

import android.content.Context
import android.widget.Toast
import org.kysecurity.mail.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object MfaResponder {
    /** [decisionKeys] come from the caller's PIN check: this runs while the app is still locked. */
    suspend fun respond(
        context: Context,
        payload: MfaChallengePayload,
        approve: Boolean,
        matchDigits: String = "",
        decisionKeys: org.kysecurity.mail.security.CredentialKeys? = null,
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
                // Leave it answerable and put the notification back: autoCancel removed the row on tap.
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
