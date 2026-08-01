package com.urlxl.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * Base class for every screen that must not be reachable while the app lock is engaged.
 *
 * The lock used to be enforced by a single `startActivity(UnlockActivity)` in
 * [com.urlxl.mail.KyPostApp.onStart], which put the PIN screen *on top of* a live, fully
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
        if (secureWindow) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
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
        if (verdict != null && startupWipeHandled.compareAndSet(false, true)) {
            redirectedToUnlock = true
            // Which message depends on whether the wipe actually finished. Announcing a completed
            // erasure over an incomplete one is the failure this branch used to have: it took a
            // bare `true` from enforceTripwire and always said "has been erased", including when
            // every step failed or when the security graph could not be built at all. In a coercive
            // hand-over that claim is what the user acts on.
            val message = when (verdict) {
                is WipeResult.Complete -> com.urlxl.mail.R.string.security_wiped_notice
                is WipeResult.Incomplete -> {
                    android.util.Log.e("LockedActivity", "Startup wipe incomplete: ${verdict.failedSteps}")
                    if (verdict.willRetry) com.urlxl.mail.R.string.security_wipe_incomplete_notice
                    else com.urlxl.mail.R.string.security_wipe_incomplete_final_notice
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
