package com.urlxl.mail.security

import android.content.Context
import com.urlxl.mail.SingletonGraph

class SecurityGraph(context: Context) {
    private val appContext = context.applicationContext

    // onWipe is a suspend lambda now: it used to be wrapped in runBlocking, which put a Room
    // teardown plus two Keystore-backed prefs commits on the main thread, reached from
    // UnlockActivity's click listener. AppLockManager.attemptPin is itself suspend, so the wipe
    // simply runs on the caller's IO context.
    val appLockManager: AppLockManager = AppLockManager(
        state = AppLockStore(appContext),
        onWipe = { SecurityWipe.wipeAndResetApp(appContext) },
    )
}

object SecurityRuntime {
    private val holder = SingletonGraph(::SecurityGraph)

    fun graph(context: Context): SecurityGraph = holder.get(context)

    /** See [com.urlxl.mail.SingletonGraph.invalidate] — used by
     *  [com.urlxl.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}
