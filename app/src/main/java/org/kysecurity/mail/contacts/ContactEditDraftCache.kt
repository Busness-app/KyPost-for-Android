package org.kysecurity.mail.contacts

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * The in-progress contact edit, held for the life of the process so a fold cannot destroy it.
 *
 * Unfolding a device is a configuration change, which destroys and recreates the Activity. This
 * screen carries the user's contact PII across roughly thirty fields, and discarding it because
 * someone opened their phone is data loss on a casual gesture.
 *
 * A saved-state Bundle is the wrong home for it: that is system-managed storage written outside
 * this app's control, and [ComposeDraftCache][org.kysecurity.mail.ComposeDraftCache] already
 * documents why message plaintext stays out of it. This holds the same line for contact plaintext —
 * in memory, process-scoped, and registered with [ProcessState] so a security wipe clears it.
 */
object ContactEditDraftCache : ProcessScopedState {

    @Volatile
    private var draft: ContactDto? = null

    /** Refuses writes until the next [take] — see ComposeDraftCache.sealed for the resurrection
     *  this prevents: a wipe clears the cache, and a write already queued lands afterwards. */
    @Volatile
    private var sealed: Boolean = false

    init {
        ProcessState.register(this)
    }

    fun save(draft: ContactDto) {
        if (sealed) return
        // An untouched form is not worth restoring, and caching it would blank a later edit's
        // prefilled fields.
        this.draft = draft.takeIf { it.fn.isNotBlank() }
    }

    fun take(): ContactDto? {
        val current = draft
        draft = null
        sealed = false
        return current
    }

    fun clear() {
        draft = null
        sealed = true
    }

    override fun resetForNewSession() = clear()
}
