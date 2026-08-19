package org.kysecurity.mail.security

import android.content.Context
import org.kysecurity.mail.SingletonGraph

class SecurityGraph(context: Context) {
    private val appContext = context.applicationContext

    val appLockStore = AppLockStore(appContext)

    val hostileLocationSettings = HostileLocationSettings(appContext)

    val appLockSettings = AppLockSettings(appContext)

    val biometricUnlockVault = BiometricUnlockVault(appContext)

    val appLockManager: AppLockManager = AppLockManager(
        state = appLockStore,
        sealer = biometricUnlockVault,
        onWipe = { SecurityWipe.wipeAndResetApp(appContext) },
    )
}

object SecurityRuntime {
    private val holder = SingletonGraph(::SecurityGraph)

    fun graph(context: Context): SecurityGraph = holder.get(context)

    fun invalidate() = holder.invalidate()
}
