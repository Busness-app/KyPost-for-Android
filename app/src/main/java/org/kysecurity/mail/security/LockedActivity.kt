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
     * True once this Activity has been redirected to the unlock screen, or is standing down for a
     * startup wipe verdict.
     *
     * Still readable by subclasses, because `onResume`, `onCreateOptionsMenu` and the async
     * callbacks they start legitimately need it. What it is no longer used for is gating
     * `onCreate` — see [onCreateUnlocked].
     */
    protected var redirectedToUnlock: Boolean = false
        private set

    /**
     * [onCreate], minus every state in which this screen must not run.
     *
     * **This replaces a convention with a signature.** The gate used to be three lines every
     * subclass had to remember to copy — `super.onCreate(...)`, a comment, `if (redirectedToUnlock)
     * return` — repeated verbatim in thirteen Activities. All thirteen got it right; the
     * fourteenth was one merge away from rendering the inbox behind the unlock screen, and no
     * compiler or test could have said so. Overriding this instead makes "do not run while locked"
     * a thing the type system enforces rather than a thing a comment asks for.
     *
     * Called only when: the startup wipe verdict is in and not terminal, and the app is unlocked.
     */
    protected abstract fun onCreateUnlocked(savedInstanceState: Bundle?)

    /** [onStart], under the same guarantee as [onCreateUnlocked]. The app can lock while this
     *  screen sits in the back stack, and `onCreate` does not run again on the way back. */
    protected open fun onStartUnlocked() = Unit

    final override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Before any subclass content view exists: enableEdgeToEdge has to be called before
        // setContentView for the display-cutout mode it sets to reach the window. UnlockActivity
        // and MfaApprovalActivity are not subclasses and call it themselves.
        enableEdgeToEdge()
        if (secureWindow) {
            window.applySecureFlag()
            // FLAG_SECURE stops capture; this stops another app drawing over the window and
            // harvesting taps meant for us. See [applyOverlayProtection].
            window.applyOverlayProtection()
        }
        if (!passesStartupTripwire()) return
        redirectToUnlockIfLocked()
        if (redirectedToUnlock || isFinishing) return
        onCreateUnlocked(savedInstanceState)
    }

    /**
     * Blocks this screen until [SecurityWipe.enforceTripwire] has ruled on whether the local
     * database is about to be destroyed. Returns false when the caller must do nothing at all.
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
            // Suspending: the graph teardown it runs quiesces a thread pool, which must not happen
            // on the main thread. See [AppRestart.relaunch].
            lifecycleScope.launch { AppRestart.relaunch(this@LockedActivity) }
            return false
        }

        reportCredentialResets()
        window.decorView.visibility = View.VISIBLE
        return true
    }

    /**
     * Tells the user, once, that an encrypted store had to be reset out from under them.
     */
    private fun reportCredentialResets() {
        val reset = credentialResetsPending(this)
        if (reset.isEmpty() || !credentialResetReported.compareAndSet(false, true)) return
        android.util.Log.e("LockedActivity", "Encrypted stores were reset: $reset")
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(org.kysecurity.mail.R.string.security_credential_reset_title)
            .setMessage(org.kysecurity.mail.R.string.security_credential_reset_message)
            .setPositiveButton(android.R.string.ok) { _, _ -> acknowledgeCredentialResets(this) }
            .setCancelable(false)
            .create()
            .showSecurely()
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
                .create()
                .showSecurely()
        }
    }

    /** The resume-time half of the gate. Final for the same reason [onCreate] is; subclasses
     *  override [onStartUnlocked]. */
    final override fun onStart() {
        super.onStart()
        // Nothing to gate while we are standing down for the tripwire — this instance is about to
        // be recreated or the task is about to be relaunched.
        if (redirectedToUnlock) return
        redirectToUnlockIfLocked()
        if (redirectedToUnlock || isFinishing) return
        onStartUnlocked()
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

        /** Likewise for the credential-reset notice — one dialog per process, not one per screen. */
        val credentialResetReported = java.util.concurrent.atomic.AtomicBoolean(false)
    }
}
