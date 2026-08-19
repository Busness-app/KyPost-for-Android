package org.kysecurity.mail

import java.util.concurrent.CopyOnWriteArrayList

/** State in a process-scoped `object` that must be reset by hand at a session boundary. */
interface ProcessScopedState {
    /** Must be safe from any thread, callable more than once, and must not throw. */
    fun resetForNewSession()
}

object ProcessState {
    private const val TAG = "ProcessState"

    private val registered = CopyOnWriteArrayList<ProcessScopedState>()

    fun register(state: ProcessScopedState) {
        registered.addIfAbsent(state)
    }

    /** Resets every registered holder, isolating failures; returns the names that failed. */
    fun resetAll(): List<String> {
        val failed = mutableListOf<String>()
        registered.forEach { state ->
            runCatching { state.resetForNewSession() }.onFailure {
                val name = state::class.java.simpleName
                failed += name
                android.util.Log.e(TAG, "Failed to reset process-scoped state: $name", it)
            }
        }
        return failed
    }
}
