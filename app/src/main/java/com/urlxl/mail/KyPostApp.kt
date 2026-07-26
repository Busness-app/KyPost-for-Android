package com.urlxl.mail

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.urlxl.mail.contacts.ContactsRuntime
import com.urlxl.mail.contacts.device.DeviceContactsRuntime
import com.urlxl.mail.push.PushNotificationDispatcher
import com.urlxl.mail.push.PushRuntime
import com.urlxl.mail.security.AppLockSettings
import com.urlxl.mail.security.SecurityRuntime
import com.urlxl.mail.security.SecurityWipe
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
            // Runs before anything reads cached data: if the encrypted app-lock state vanished
            // while the tripwire says a lock was configured, the local database is destroyed
            // rather than served up behind a lock that now reports itself as disabled.
            if (SecurityWipe.enforceTripwire(this@KyPostApp)) return@launch
            runCatching { DeviceContactsRuntime.graph(this@KyPostApp).bootstrapIfEnabled() }
                .onFailure { android.util.Log.e("KyPostApp", "Failed to bootstrap device contacts", it) }
        }

        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        // App moved to the foreground. The unlock screen is no longer launched from here: every
        // gated Activity now redirects to it in its own onCreate/onStart (see
        // com.urlxl.mail.security.LockedActivity), which is what makes the lock unbypassable
        // rather than a screen laid on top of a live app.
        applyLockGrace()

        // Nothing below runs while locked. These are credential-bearing network syncs; kicking
        // them off behind the unlock screen both leaks activity and pointlessly fails whenever
        // the credential gate is on and the device secret is still wrapped.
        if (SecurityRuntime.graph(this).appLockManager.locked.value) return

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

    /**
     * Locking is deferred by [AppLockSettings.graceMillis] rather than firing the instant the app
     * loses the foreground.
     *
     * Every outbound intent this app makes leaves the process: the attachment picker, the
     * attachment-viewer chooser, the QR scanner (a GMS process), the "Open in webmail" handoff.
     * Each one stops the last Activity, which fired `lockNow()` immediately — and because
     * [com.urlxl.mail.security.LockedActivity] *finishes* rather than layering, coming back
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
            SecurityRuntime.graph(this).appLockManager.lockNow()
            backgroundedAtElapsedMs = 0L
            return
        }
        backgroundedAtElapsedMs = SystemClock.elapsedRealtime()
    }

    private fun applyLockGrace() {
        val backgroundedAt = backgroundedAtElapsedMs
        backgroundedAtElapsedMs = 0L
        if (backgroundedAt == 0L) return
        // elapsedRealtime, not wall clock: a wall-clock window is defeated by changing the device
        // date, exactly as AppLockState.lockoutUntilElapsedMs already documents.
        val away = SystemClock.elapsedRealtime() - backgroundedAt
        if (away >= AppLockSettings(this).graceMillis()) {
            SecurityRuntime.graph(this).appLockManager.lockNow()
        }
    }
}
