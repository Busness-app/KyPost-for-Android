package org.kysecurity.mail.security

import android.app.Activity
import android.widget.Toast
import org.kysecurity.mail.R

/** Route every result through here; no screen outside this file may test for Success. */
suspend fun Activity.resolvePinAttempt(result: UnlockAttemptResult): Boolean = when (result) {
    is UnlockAttemptResult.Success -> true
    is UnlockAttemptResult.Rejected -> false
    is UnlockAttemptResult.VerifierUnavailable -> {
        // Not a wrong PIN, and it does not advance the wipe threshold.
        Toast.makeText(applicationContext, R.string.security_verifier_unavailable, Toast.LENGTH_LONG).show()
        false
    }
    is UnlockAttemptResult.Wiped -> {
        announceWipeAndRelaunch(R.string.security_wiped_notice, failedSteps = null)
        false
    }
    is UnlockAttemptResult.WipeFailed -> {
        // Retry is only promised while SecurityWipe still resumes; MAX_WIPE_RESUMES ends that.
        val message =
            if (result.willRetry) R.string.security_wipe_incomplete_notice
            else R.string.security_wipe_incomplete_final_notice
        announceWipeAndRelaunch(message, result.failedSteps)
        false
    }
}

/** App-context Toast: finishAffinity() follows and would drop one bound to this Activity. */
private suspend fun Activity.announceWipeAndRelaunch(messageRes: Int, failedSteps: List<String>?) {
    if (failedSteps != null) {
        android.util.Log.e("PinGate", "Wipe incomplete: $failedSteps")
    }
    Toast.makeText(applicationContext, messageRes, Toast.LENGTH_LONG).show()
    AppRestart.relaunch(this)
}
