package org.kysecurity.mail.security

import android.app.Activity
import android.widget.Toast
import org.kysecurity.mail.R

/**
 * Turns an [UnlockAttemptResult] into "may this screen proceed?", handling the two outcomes that
 * are not about the PIN at all.
 *
 * [UnlockAttemptResult.Wiped] and [UnlockAttemptResult.WipeFailed] mean [SecurityWipe] **has
 * already run**: the database is deleted, every SharedPreferences file this app owns is gone, the
 * synced OS contact rows are removed and the device has been deregistered from the relay. Three
 * call sites used to write `verifyPinThrottled(pin) is UnlockAttemptResult.Success` and treat both
 * as a plain `false` — so a wipe reached from the settings screen or the MFA approval prompt showed
 * "Incorrect PIN", left the Activity running against a closed database, and never relaunched. Only
 * [UnlockActivity] handled it.
 *
 * Routing every caller through here is what makes that unrepresentable: the `when` below is
 * exhaustive over the sealed class, so a new outcome is a compile error rather than a silent
 * `false`. **No screen outside this file may test the result for `Success` directly.**
 *
 * Returns `true` only for [UnlockAttemptResult.Success]. On either wipe outcome it relaunches into
 * a fresh first-run state, so the caller's `false` branch runs against an Activity that is already
 * finishing — which is harmless, and simpler than making every caller understand the difference.
 */
suspend fun Activity.resolvePinAttempt(result: UnlockAttemptResult): Boolean = when (result) {
    is UnlockAttemptResult.Success -> true
    is UnlockAttemptResult.Rejected -> false
    is UnlockAttemptResult.VerifierUnavailable -> {
        // Not a wrong PIN, and the user must not be told it was one — the correct PIN will keep
        // "failing" until they reinstall, and every screen that shows "Incorrect PIN" here invites
        // them to burn the remaining attempts against a wipe threshold this outcome deliberately
        // does not advance. Say what actually happened.
        Toast.makeText(applicationContext, R.string.security_verifier_unavailable, Toast.LENGTH_LONG).show()
        false
    }
    is UnlockAttemptResult.Wiped -> {
        announceWipeAndRelaunch(R.string.security_wiped_notice, failedSteps = null)
        false
    }
    is UnlockAttemptResult.WipeFailed -> {
        // Two different messages: the wipe is only retried while SecurityWipe is still resuming it.
        // Once MAX_WIPE_RESUMES is reached nothing will re-run by itself, so promising a retry
        // there tells the user their data will be erased when it will not be. The relaunch below
        // then lands on LockedActivity's terminal block, which is where that state is enforced
        // rather than merely announced.
        val message =
            if (result.willRetry) R.string.security_wipe_incomplete_notice
            else R.string.security_wipe_incomplete_final_notice
        announceWipeAndRelaunch(message, result.failedSteps)
        false
    }
}

/**
 * Tells the user their data is gone (or may not be) and rebuilds the process graphs.
 *
 * The Toast is built against the application context because [AppRestart.relaunch] calls
 * `finishAffinity()` immediately afterwards — a Toast bound to a finishing Activity's context can be
 * dropped, and this is the one message that must not be.
 *
 * Relaunching on the *incomplete* path too is deliberate: [SecurityWipe] leaves its in-progress
 * marker set, and [org.kysecurity.mail.KyPostApp] re-runs the whole wipe on the next start.
 */
private fun Activity.announceWipeAndRelaunch(messageRes: Int, failedSteps: List<String>?) {
    if (failedSteps != null) {
        android.util.Log.e("PinGate", "Wipe incomplete: $failedSteps")
    }
    Toast.makeText(applicationContext, messageRes, Toast.LENGTH_LONG).show()
    AppRestart.relaunch(this)
}
