package org.kysecurity.mail

import android.content.Context

/**
 * Thread-safe, context-scoped lazy holder shared by each package's `XGraph`/`XRuntime` pair
 * (mail/MailGraph, contacts/ContactsGraph, data/DataRuntime, push/PushRuntime) so the
 * double-checked-locking singleton logic lives in one place instead of four.
 */
/**
 * A graph that owns something needing an orderly shutdown when it is dropped.
 */
interface ClosableGraph {
    fun closeGraph()
}

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
     * Protection picks disk-backed vs in-memory Room at [org.kysecurity.mail.data.DataGraph]
     * construction time, and a security wipe closes the database out from under the old graph.
     * Both used to require killing the process, which is why [org.kysecurity.mail.security.AppRestart]
     * no longer does.
     */
    fun invalidate() {
        synchronized(this) {
            (instance as? ClosableGraph)?.let { graph ->
                runCatching { graph.closeGraph() }
                    .onFailure { android.util.Log.e("SingletonGraph", "Graph teardown failed", it) }
            }
            instance = null
        }
    }

    /**
     * Atomically removes and returns the cached instance, or null if one was never built.
     *
     * Taking it also means no later caller can be handed the instance that is about to be closed —
     * which `invalidate()` alone only guarantees for callers that arrive after it returns.
     */
    fun take(): T? = synchronized(this) { instance.also { instance = null } }

    /**
     * The cached instance if one exists, without building it.
     *
     * For code that wants to act on a graph only when the process already has one. A plain [get]
     * during a security wipe rebuilt the graph the wipe had just torn down — and rebuilt it against
     * settings the wipe had already deleted, so [org.kysecurity.mail.data.DataGraph] read Hostile
     * Location Protection as off and recreated `kypost_mail.db` on disk.
     */
    fun peek(): T? = instance
}
