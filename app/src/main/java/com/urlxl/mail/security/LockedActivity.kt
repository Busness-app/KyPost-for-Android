package com.urlxl.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity

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

    protected fun isLocked(): Boolean = SecurityRuntime.graph(this).appLockManager.locked.value

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
        redirectToUnlockIfLocked()
    }

    /** The resume-time half of the gate: the app can lock while this screen sits in the back
     *  stack, and `onCreate` does not run again on the way back. */
    override fun onStart() {
        super.onStart()
        redirectToUnlockIfLocked()
    }

    private fun redirectToUnlockIfLocked() {
        if (redirectedToUnlock || isFinishing || !isLocked()) return
        redirectedToUnlock = true
        startActivity(Intent(this, UnlockActivity::class.java))
        finish()
    }
}
