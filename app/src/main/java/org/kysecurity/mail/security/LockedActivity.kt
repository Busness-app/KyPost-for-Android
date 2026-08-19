package org.kysecurity.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch

abstract class LockedActivity : AppCompatActivity() {

    protected open val secureWindow: Boolean = true

    /** [AppLockManager.isLockedNow], not the flow value: the grace window may have expired. */
    protected fun isLocked(): Boolean = SecurityRuntime.graph(this).appLockManager.isLockedNow()

    protected var redirectedToUnlock: Boolean = false
        private set

    /** Called only when the startup wipe verdict is in, not terminal, and the app is unlocked. */
    protected abstract fun onCreateUnlocked(savedInstanceState: Bundle?)

    /** [onStart], under the same guarantee as [onCreateUnlocked]. The app can lock while this
     *  screen sits in the back stack, and `onCreate` does not run again on the way back. */
    protected open fun onStartUnlocked() = Unit

    final override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // enableEdgeToEdge must precede setContentView for its cutout mode to reach the window.
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

    /** Blocks until [SecurityWipe.enforceTripwire] has ruled; false means do nothing at all. */
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

        // First screen to observe a startup wipe relaunches; the CAS keeps it to exactly one.
        val verdict = SecurityWipe.startupVerdict.getCompleted()

        // Unreadable Keystore: neither answer is safe, so show nothing. Transient, not terminal.
        val lockTripwireUnreadable =
            runCatching { AppLockStore(this).tripwireState() }.getOrNull() == TripwireState.UNREADABLE
        // Checked here because isEnabled() resolves UNREADABLE to true, hiding it from callers.
        val protectionUnreadable = runCatching { HostileLocationSettings(this).state() }
            .getOrNull() == HostileLocationState.UNREADABLE
        if (lockTripwireUnreadable || protectionUnreadable) {
            redirectedToUnlock = true
            blockOnUnreadableTripwire()
            return false
        }

        // Terminal, and checked before the one-shot below because this state is not one-shot.
        if (verdict is WipeResult.Incomplete && !verdict.willRetry) {
            redirectedToUnlock = true
            blockOnAbandonedWipe(verdict.failedSteps)
            return false
        }

        if (verdict != null && startupWipeHandled.compareAndSet(false, true)) {
            redirectedToUnlock = true
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
        reportStrandedDownloads()
        window.decorView.visibility = View.VISIBLE
        return true
    }

    /** A wipe that finished cleanly can still have left decrypted attachments in shared Downloads,
     *  which the app cannot delete and the user can. Saying so is the whole point: the alternative
     *  is a "your data has been erased" notice that is not true. */
    private fun reportStrandedDownloads() {
        val stranded = SecurityWipe.strandedDownloadsPending(this)
        if (stranded <= 0 || !strandedDownloadsReported.compareAndSet(false, true)) return
        android.util.Log.e("LockedActivity", "Wipe left $stranded attachment(s) in shared Downloads")
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(org.kysecurity.mail.R.string.security_stranded_downloads_title)
            .setMessage(
                resources.getQuantityString(
                    org.kysecurity.mail.R.plurals.security_stranded_downloads_message,
                    stranded,
                    stranded,
                ),
            )
            .setPositiveButton(android.R.string.ok) { _, _ -> SecurityWipe.acknowledgeStrandedDownloads(this) }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    private fun reportCredentialResets() {
        val reset = credentialResetsPending(this)
        if (reset.isEmpty() || !credentialResetReported.compareAndSet(false, true)) return
        android.util.Log.e("LockedActivity", "Encrypted stores were reset: $reset")
        // Losing the database key costs the cached mail, not just a re-establishable credential.
        val message = if (org.kysecurity.mail.data.DATABASE_NAME in reset) {
            org.kysecurity.mail.R.string.security_credential_reset_message_mail_lost
        } else {
            org.kysecurity.mail.R.string.security_credential_reset_message
        }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(org.kysecurity.mail.R.string.security_credential_reset_title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> acknowledgeCredentialResets(this) }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    /** Transient device condition: asks for a restart, unlike [blockOnAbandonedWipe]. */
    private fun blockOnUnreadableTripwire() {
        android.util.Log.e("LockedActivity", "The tripwire key store is unreadable; refusing to open")
        window.decorView.visibility = View.INVISIBLE
        window.decorView.post {
            if (isFinishing || isDestroyed) return@post
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setCancelable(false)
                .setTitle(org.kysecurity.mail.R.string.security_tripwire_unreadable_title)
                .setMessage(org.kysecurity.mail.R.string.security_tripwire_unreadable_message)
                .setPositiveButton(org.kysecurity.mail.R.string.security_wipe_blocked_close) { _, _ ->
                    finishAffinity()
                }
                .create()
                .showSecurely()
        }
    }

    /** Posted because this runs from onCreate, before the window has a token for a dialog. */
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
        /** One-shot: later screens must not bounce the task again on the same verdict. */
        val startupWipeHandled = java.util.concurrent.atomic.AtomicBoolean(false)

        /** Likewise for the credential-reset notice — one dialog per process, not one per screen. */
        val credentialResetReported = java.util.concurrent.atomic.AtomicBoolean(false)

        /** And for the stranded-downloads notice, for the same reason. */
        val strandedDownloadsReported = java.util.concurrent.atomic.AtomicBoolean(false)
    }
}
