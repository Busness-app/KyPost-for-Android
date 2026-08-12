package org.kysecurity.mail.security

import android.content.Context
import org.kysecurity.mail.SingletonGraph

class SecurityGraph(context: Context) {
    private val appContext = context.applicationContext

    /**
     * The single [AppLockStore] for the process.
     *
     * Nine ad-hoc `AppLockStore(context)` constructions used to exist — two of them in the same
     * function ([org.kysecurity.mail.push.PushRepository.savePairing]) — and each one builds its own
     * `MasterKey` and `EncryptedSharedPreferences`, meaning a Keystore access and a Tink keyset
     * load apiece. [org.kysecurity.mail.push.SecurePairingStore]'s KDoc already diagnosed exactly this
     * pattern for the pairing store and fixed it there; the same reasoning applies here.
     */
    val appLockStore = AppLockStore(appContext)

    /** Likewise for the protection flag, which was constructed ten times over — including once
     *  per attachment chip inside a `forEach` in `EmailDetailActivity`. */
    val hostileLocationSettings = HostileLocationSettings(appContext)

    val appLockSettings = AppLockSettings(appContext)

    // onWipe is a suspend lambda now: it used to be wrapped in runBlocking, which put a Room
    // teardown plus two Keystore-backed prefs commits on the main thread, reached from
    // UnlockActivity's click listener. AppLockManager.attemptPin is itself suspend, so the wipe
    // simply runs on the caller's IO context.
    val appLockManager: AppLockManager = AppLockManager(
        state = appLockStore,
        onWipe = { SecurityWipe.wipeAndResetApp(appContext) },
    )
}

object SecurityRuntime {
    private val holder = SingletonGraph(::SecurityGraph)

    fun graph(context: Context): SecurityGraph = holder.get(context)

    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}
