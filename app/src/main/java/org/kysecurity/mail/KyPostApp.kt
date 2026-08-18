package org.kysecurity.mail

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.push.PushNotificationDispatcher
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.security.AppLockSettings
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.SecurityWipe
import org.kysecurity.mail.security.WipeResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Process-level wiring for push/pull delivery. Observes the process lifecycle so that every time
 * the app foregrounds we re-read the authoritative delivery mode and, when in "App Pull" mode,
 * kick an immediate pull — complementing the WorkManager periodic baseline.
 */
class KyPostApp : Application(), DefaultLifecycleObserver {

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super<Application>.onCreate()
        PushNotificationDispatcher.ensureChannel(this)

        appScope.launch {
            // Build the security graph HERE, on IO, before any Activity asks for it.
            //
            // Constructing it forces AppLockStore's EncryptedSharedPreferences, which is a
            // MasterKey round trip into the AndroidKeyStore plus a Tink keyset load. The first
            // caller was LockedActivity.onCreate — via isLocked() — so that cost landed on the main
            // thread inside the first Activity of every cold start, including the FCM-woken process
            // that has to render MfaApprovalActivity promptly. SecurityGraph's own KDoc already
            // diagnosed this cost and fixed the *number* of times it was paid, not the thread.
            runCatching { SecurityRuntime.graph(this@KyPostApp) }
                .onFailure { android.util.Log.e("KyPostApp", "Failed to warm the security graph", it) }

            // If the encrypted app-lock state vanished while the tripwire says a lock was
            // configured, the local database is destroyed rather than served up behind a lock that
            // now reports itself as disabled.
            val verdict = runCatching { SecurityWipe.enforceTripwire(this@KyPostApp) }
                .onFailure { android.util.Log.e("KyPostApp", "Startup tripwire check failed", it) }
                .getOrElse { WipeResult.Incomplete(listOf("startupTripwireCheck")) }
            SecurityWipe.startupVerdict.complete(verdict)
            if (verdict != null) return@launch

            runCatching { DeviceContactsRuntime.graph(this@KyPostApp).bootstrapIfEnabled() }
                .onFailure { android.util.Log.e("KyPostApp", "Failed to bootstrap device contacts", it) }
        }

        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        // App moved to the foreground. The unlock screen is no longer launched from here: every
        // gated Activity now redirects to it in its own onCreate/onStart (see
        // org.kysecurity.mail.security.LockedActivity), which is what makes the lock unbypassable
        // rather than a screen laid on top of a live app.
        applyLockGrace()

        // Nothing below runs while locked. These are credential-bearing network syncs; kicking
        // them off behind the unlock screen both leaks activity and pointlessly fails whenever
        // the credential gate is on and the device secret is still wrapped.
        //
        // isLockedNow(), not locked.value — AppLockManager's own contract says a security decision
        // must use the former, because the flow only changes when something calls lockNow() and a
        // background grace window may have expired with nothing having done so. applyLockGrace()
        // above happens to cover this today; relying on that made the correctness of these three
        // syncs depend on the order of two lines in this method.
        // The wipe verdict outranks the lock. `SecurityWipe.blockedByAbandonedWipe` exists for
        // "the non-Activity entry points that cannot go through LockedActivity's terminal block",
        // and this is one of them: with the lock off (the default) an abandoned wipe still left
        // every foreground kicking three credential-bearing syncs, which repopulated the OS
        // contacts provider and the mail cache the wipe was supposed to have destroyed — while
        // every screen sat on "manual recovery required".
        if (SecurityWipe.blockedByAbandonedWipe(this)) return
        // Likewise before the verdict is in at all: enforceTripwire may be mid-wipe on the IO
        // scope right now, and a sync racing it writes rows behind the deletion. onStart fires
        // again on the next foreground, by which time the verdict has landed.
        if (!SecurityWipe.startupVerdict.isCompleted) return

        if (SecurityRuntime.graph(this).appLockManager.isLockedNow()) return

        runCatching { PushRuntime.graph(this).pullCoordinator.pullNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to pull", it) }
        runCatching { ContactsRuntime.graph(this).coordinator.syncNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to sync contacts (relay)", it) }
        runCatching { DeviceContactsRuntime.graph(this).coordinator.syncNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to sync contacts (device)", it) }
    }

    /**
     * When the app went to the background, on the monotonic timebase. Zero means "foreground, or
     * the grace window has already been resolved".
     */
    private var backgroundedAtElapsedMs: Long = 0L

    /** Fires [AppLockSettings.graceMillis] after the app backgrounds; see [onStop]. */
    private val lockHandler = Handler(Looper.getMainLooper())
    private val engageLock = Runnable {
        backgroundedAtElapsedMs = 0L
        SecurityRuntime.graph(this).appLockManager.lockNow()
    }

    /**
     * Locking is deferred by [AppLockSettings.graceMillis] rather than firing the instant the app
     * loses the foreground.
     *
     * Every outbound intent this app makes leaves the process: the attachment picker, the
     * attachment-viewer chooser, the QR scanner (a GMS process), the "Open in webmail" handoff.
     * Each one stops the last Activity, which fired `lockNow()` immediately — and because
     * [org.kysecurity.mail.security.LockedActivity] *finishes* rather than layering, coming back
     * destroyed the screen outright. Attaching a file to a message therefore deleted the message:
     * recipients, subject, body and every attachment already picked, with no draft to recover.
     *
     * The grace window is the standard resolution (every banking app does this) and is
     * user-configurable, defaulting to 30s — long enough for a file picker round trip, short
     * enough that a pocketed phone re-locks.
     */
    override fun onStop(owner: LifecycleOwner) {
        val grace = AppLockSettings(this).graceMillis()
        if (grace <= 0L) {
            lockHandler.removeCallbacks(engageLock)
            SecurityRuntime.graph(this).appLockManager.lockNow()
            backgroundedAtElapsedMs = 0L
            return
        }
        backgroundedAtElapsedMs = SystemClock.elapsedRealtime()
        // Two mechanisms for one deadline, because neither is sufficient alone. The Handler is what
        // actually flips the lock state and drops the cached credential keys, but it runs on
        // `uptimeMillis`, which stops advancing in deep sleep. `scheduleLock` records the same
        // deadline on `elapsedRealtime`, so AppLockManager.isLockedNow() answers correctly even if
        // the callback has not fired — see that method.
        SecurityRuntime.graph(this).appLockManager.scheduleLock(backgroundedAtElapsedMs + grace)
        lockHandler.removeCallbacks(engageLock)
        lockHandler.postDelayed(engageLock, grace)
    }

    /**
     * Resolves the grace window on the way back to the foreground, and cancels the pending
     * [engageLock] so returning inside the window doesn't re-lock a screen the user is looking at.
     *
     * Still re-checks the elapsed time itself rather than trusting the cancelled callback: a
     * `Handler` callback does not survive process death, and Doze can hold a non-exact
     * `postDelayed` past its deadline. Whichever of the two notices first, the app locks.
     */
    private fun applyLockGrace() {
        lockHandler.removeCallbacks(engageLock)
        val appLockManager = SecurityRuntime.graph(this).appLockManager
        val backgroundedAt = backgroundedAtElapsedMs
        backgroundedAtElapsedMs = 0L
        if (backgroundedAt == 0L) {
            appLockManager.cancelScheduledLock()
            return
        }
        // elapsedRealtime, not wall clock: a wall-clock window is defeated by changing the device
        // date, exactly as AppLockState.lockoutUntilElapsedMs already documents.
        val away = SystemClock.elapsedRealtime() - backgroundedAt
        if (away >= AppLockSettings(this).graceMillis()) {
            appLockManager.lockNow()
        } else {
            appLockManager.cancelScheduledLock()
        }
    }

    /**
     * Drops the opened PGP private key under real memory pressure.
     *
     * **[level] is load-bearing, and ignoring it undid the grace window.** `TRIM_MEMORY_UI_HIDDEN`
     * fires every time this app's UI goes away — the attachment picker, the QR scanner, the webmail
     * handoff, or the user glancing at a text message. Clearing on every trim signal therefore
     * meant a BiometricPrompt on return from each of those, on exactly the round trips [onStop]'s
     * grace window exists to make survivable, and it contradicted
     * [org.kysecurity.mail.pgp.EnrollmentSession]'s own contract that the key is "bound to the window
     * the user already configured at 'Lock after: …' rather than to a second concept of its own".
     *
     * `TRIM_MEMORY_RUNNING_LOW` and above are the levels that actually mean the process is a
     * candidate for a kill, which is the case worth paying a prompt for. The ordinary
     * background transition is [onStop]'s job, and it does it on the user's configured deadline.
     *
     * Deliberately NOT routed through `InMemoryPlaintext`. Its KDoc records that it is not called
     * from `AppLockManager.lockNow()` because the compose draft cache must survive an ordinary
     * lock; the key holder has the opposite requirement, so it gets its own call rather than a
     * change to that policy.
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_RUNNING_LOW) org.kysecurity.mail.pgp.EnrollmentSession.clear()
    }
}
