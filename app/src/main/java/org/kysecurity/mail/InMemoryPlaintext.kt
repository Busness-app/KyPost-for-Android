package org.kysecurity.mail

/** Not called from `AppLockManager.lockNow()`: the draft cache must survive an ordinary lock. */
object InMemoryPlaintext {
    /** Names of holders that failed to clear; empty on success. */
    fun clearAll(): List<String> = ProcessState.resetAll()
}
