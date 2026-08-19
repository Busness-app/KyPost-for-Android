package org.kysecurity.mail

import android.content.Context

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

    /** Drops the cached instance: graph construction reads settings that can change at runtime. */
    fun invalidate() {
        synchronized(this) {
            (instance as? ClosableGraph)?.let { graph ->
                runCatching { graph.closeGraph() }
                    .onFailure { android.util.Log.e("SingletonGraph", "Graph teardown failed", it) }
            }
            instance = null
        }
    }

    /** Atomically removes the instance, so no later caller is handed the one about to be closed. */
    fun take(): T? = synchronized(this) { instance.also { instance = null } }

    /** The cached instance without building one: a `get()` during a wipe rebuilt what it tore down. */
    fun peek(): T? = instance
}
