package com.urlxl.mail

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.urlxl.mail.contacts.ContactsRuntime
import com.urlxl.mail.contacts.device.DeviceContactsRuntime
import com.urlxl.mail.push.PushNotificationDispatcher
import com.urlxl.mail.push.PushRuntime
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
        // gated Activity now redirects to it in its own onStart (see
        // com.urlxl.mail.security.LockedActivity), which is what makes the lock unbypassable
        // rather than a screen laid on top of a live app.
        //
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

    override fun onStop(owner: LifecycleOwner) {
        SecurityRuntime.graph(this).appLockManager.lockNow()
    }
}
