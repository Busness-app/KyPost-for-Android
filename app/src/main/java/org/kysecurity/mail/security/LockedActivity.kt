package org.kysecurity.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch

/**
 * Base class for every screen that must not be reachable while the app lock is engaged.
 *
 * The lock used to be enforced by a single `startActivity(UnlockActivity)` in
 * [org.kysecurity.mail.KyPostApp.onStart], which put the PIN screen *on top of* a live, fully
 * populated app — one Back press revealed the inbox, and any other entry point (a notification
 * tap, a `kypost://` deep link, the MFA screen) never passed through it at all. Enforcing it per
 * Activity in [onStart], and finishing rather than layering, is what makes it an actual gate:
 * there is no Activity left underneath to fall back to.
 *
 * [secureWindow] additionally sets `FLAG_SECURE` on every subclass. This was previously applied
 * ad hoc and had been missed on the contacts screens and the pairing screen, which display email
 * addresses, phone numbers, PGP keys, the server URL and the device ID.
 */
abstract class LockedActivity : AppCompatActivity() {

    /** Overridable only so a future screen with a genuine reason (e.g. a share/print preview) can
     *  opt out deliberately; no current screen does. */
    protected open val secureWindow: Boolean = true

    /** [AppLockManager.isLockedNow], not the flow's current value: a screen resumed after the
     *  background grace window expired must gate on the window having expired, not on whether
     *  anything happened to call `lockNow()` in the meantime. */
    protected fun isLocked(): Boolean = SecurityRuntime.graph(this).appLockManager.isLockedNow()

    /**
     * True once this Activity has been redirected to the unlock screen. Subclasses whose `onCreate`
     * does real work — network calls, database reads, executor dispatch — must check this
     * immediately after `super.onCreate(...)` and return.
     *
     * `onCreate` always runs to completion before `onStart`, so gating only in `onStart` (as this
     * class originally did) meant every subclass's entire `onCreate` body executed *while the app
     * was locked*. `EmailDetailActivity` fired an authenticated `markRead` mutation at the server
     * from there, so a notification tap on a locked app silently marked mail read — destroying the
     * "was this opened?" signal the real user would otherwise have had — before the PIN screen
     * appeared.
     */
    protected var redirectedToUnlock: Boolean = false
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Here rather than in each subclass: this runs from the subclass's `super.onCreate(...)`,
        // which is the last point before its `setContentView` — where enableEdgeToEdge has to be
        // called for the display-cutout mode it sets to reach the window. UnlockActivity and
        // MfaApprovalActivity are not subclasses and call it themselves.
        enableEdgeToEdge()
        if (secureWindow) {
            window.applySecureFlag()
        }
        if (!passesStartupTripwire()) return
        redirectToUnlockIfLocked()
    }

    /**
     * Blocks this screen until [SecurityWipe.enforceTripwire] has ruled on whether the local
     * database is about to be destroyed. Returns false when the caller must do nothing at all.
     *
     * The tripwire decides whether the encrypted app-lock state vanished under a configured lock —
     * i.e. whether someone deleted the keyset to disable the lock. It runs on a background
     * coroutine started from `Application.onCreate`, which returns before this Activity is created,
     * so it used to race the first screen: an attacker got a fully populated inbox rendered from
     * the cache for as long as the Keystore round trip took, and the wipe landed afterwards,
     * tearing the database out from under a live screen. `Application.onCreate` cannot make the
     * "runs before anything reads cached data" promise its comment used to make, so the gate has to
     * be here.
     *
     * While the verdict is pending this sets [redirectedToUnlock] and returns false, which is
     * exactly the contract every subclass already honours (`if (redirectedToUnlock) return`
     * immediately after `super.onCreate`) — so no subclass runs its database reads, network calls
     * or executor dispatch in the meantime. Blanking the window alone would have hidden the render
     * while letting all of that happen anyway. When the verdict lands clean the Activity is simply
     * recreated, and the check below is synchronous from then on: the deferred is process-scoped,
     * so this costs at most one recreate on the first screen of a cold start.
     */
    // getCompleted() below is guarded by the isCompleted check that opens this function.
    @OptIn(ExperimentalCoroutinesApi::class)
    private fun passesStartupTripwire(): Boolean {
        if (!SecurityWipe.startupVerdict.isCompleted) {
            redirectedToUnlock = true
            window.decorView.visibility = View.INVISIBLE
            lifecycleScope.launch {
                SecurityWipe.startupVerdict.await()
                if (!isFinishing && !isDestroyed) recreate()
            }
            return false
        }

        // First screen to observe a startup wipe: tell the user, rebuild every graph (Mail and
        // Contacts still hold DAO handles on the database SecurityWipe just closed) and restart
        // into a coherent first-run state. The wipe reset the app lock, so MainActivity routes
        // straight to pairing — UnlockActivity would prompt for a PIN that no longer exists. The
        // CAS makes it exactly one screen: the others come up after the relaunch and carry on.
        val verdict = SecurityWipe.startupVerdict.getCompleted()

        // Terminal, and checked before the one-shot below because it is NOT one-shot: the wipe
        // gave up with steps still failing, so plaintext mail, contacts or attachments may be on
        // this device right now. Relaunching into a first-run screen — what the branch below does —
        // presents a clean, usable app over exactly that, which is the same false "your data is
        // gone" claim in a different form. There is nothing here it is safe to show, and only a
        // reinstall clears it, so every gated screen blocks on every launch until one happens.
        if (verdict is WipeResult.Incomplete && !verdict.willRetry) {
            redirectedToUnlock = true
            blockOnAbandonedWipe(verdict.failedSteps)
            return false
        }

        if (verdict != null && startupWipeHandled.compareAndSet(false, true)) {
            redirectedToUnlock = true
            // Which message depends on whether the wipe actually finished. Announcing a completed
            // erasure over an incomplete one is the failure this branch used to have: it took a
            // bare `true` from enforceTripwire and always said "has been erased", including when
            // every step failed or when the security graph could not be built at all. In a coercive
            // hand-over that claim is what the user acts on.
            val message = when (verdict) {
                is WipeResult.Complete -> org.kysecurity.mail.R.string.security_wiped_notice
                is WipeResult.Incomplete -> {
                    android.util.Log.e("LockedActivity", "Startup wipe incomplete: ${verdict.failedSteps}")
                    if (verdict.willRetry) org.kysecurity.mail.R.string.security_wipe_incomplete_notice
                    else org.kysecurity.mail.R.string.security_wipe_incomplete_final_notice
                }
            }
            android.widget.Toast.makeText(
                applicationContext,
                message,
                android.widget.Toast.LENGTH_LONG,
            ).show()
            AppRestart.relaunch(this)
            return false
        }

        window.decorView.visibility = View.VISIBLE
        return true
    }

    /**
     * The permanent "wipe incomplete — manual recovery required" state: a non-dismissable notice
     * over a blank window, and the only way out is closing the app.
     *
     * Posted rather than shown inline because this runs from `onCreate`, before the window has a
     * token to attach a dialog to.
     */
    private fun blockOnAbandonedWipe(failedSteps: List<String>) {
        android.util.Log.e("LockedActivity", "Wipe abandoned; blocking the app. Failed steps: $failedSteps")
        window.decorView.visibility = View.INVISIBLE
        window.decorView.post {
            if (isFinishing || isDestroyed) return@post
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setCancelable(false)
                .setTitle(org.kysecurity.mail.R.string.security_wipe_blocked_title)
                .setMessage(org.kysecurity.mail.R.string.security_wipe_incomplete_final_notice)
                .setPositiveButton(org.kysecurity.mail.R.string.security_wipe_blocked_close) { _, _ ->
                    finishAffinity()
                }
                .show()
        }
    }

    /** The resume-time half of the gate: the app can lock while this screen sits in the back
     *  stack, and `onCreate` does not run again on the way back. */
    override fun onStart() {
        super.onStart()
        // Nothing to gate while we are standing down for the tripwire — this instance is about to
        // be recreated or the task is about to be relaunched.
        if (redirectedToUnlock) return
        redirectToUnlockIfLocked()
    }

    private fun redirectToUnlockIfLocked() {
        if (redirectedToUnlock || isFinishing || !isLocked()) return
        redirectedToUnlock = true
        startActivity(Intent(this, UnlockActivity::class.java))
        finish()
    }

    private companion object {
        /** One-shot across the process: the first screen to observe a startup wipe rebuilds the
         *  graphs and relaunches, and the screens that come up afterwards must not bounce the task
         *  again on the same verdict. */
        val startupWipeHandled = java.util.concurrent.atomic.AtomicBoolean(false)
    }
}
