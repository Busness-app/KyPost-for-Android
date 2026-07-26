package com.urlxl.mail

import android.content.Context

/**
 * Thread-safe, context-scoped lazy holder shared by each package's `XGraph`/`XRuntime` pair
 * (mail/MailGraph, contacts/ContactsGraph, data/DataRuntime, push/PushRuntime) so the
 * double-checked-locking singleton logic lives in one place instead of four.
 */
class SingletonGraph<T>(private val factory: (Context) -> T) {
    @Volatile
    private var instance: T? = null

    fun get(context: Context): T {
        return instance ?: synchronized(this) {
            instance ?: factory(context.applicationContext).also { instance = it }
        }
    }

    /**
     * Drops the cached instance so the next [get] rebuilds it from scratch. Exists for settings
     * that change how a graph is constructed rather than how it behaves — Hostile Location
     * Protection picks disk-backed vs in-memory Room at [com.urlxl.mail.data.DataGraph]
     * construction time, and a security wipe closes the database out from under the old graph.
     * Both used to require killing the process, which is why [com.urlxl.mail.security.AppRestart]
     * no longer does.
     */
    fun invalidate() {
        synchronized(this) { instance = null }
    }
}
