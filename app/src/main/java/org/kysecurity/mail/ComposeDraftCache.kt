package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment

/**
 * The in-progress composition, held for the life of the process so the app lock cannot destroy it.
 *
 * [org.kysecurity.mail.security.LockedActivity] *finishes* a gated screen rather than layering the
 * unlock prompt over it — which is what makes the lock unbypassable, and is worth keeping. The cost
 * was that any lock while composing discarded the message outright: recipients, subject, body and
 * every attachment already picked, with nothing to recover. The grace window in
 * [KyPostApp.onStop] stops the common case (a file-picker round trip) from locking at all; this
 * covers the rest.
 *
 * Deliberately in-memory and process-scoped, not on disk. The thing being survived is Activity
 * destruction, not process death — and a disk-backed draft would write message plaintext into the
 * app sandbox, which is exactly what Hostile Location Protection exists to prevent. A cache that
 * dies with the process needs no special-casing for that mode at all.
 */
object ComposeDraftCache : ProcessScopedState {
    @Volatile
    private var draft: CachedDraft? = null

    /**
     * Refuses writes until the next [take].
     *
     * `ComposeActivity.onStop` stashes the draft from `bodyEditor.exportHtml`, which is an
     * **asynchronous** callback on the main looper. A wipe clears this cache on an IO thread as
     * its very first step, and a callback already queued before that then landed afterwards and
     * put the victim's unsent message — recipients, body, attachments — straight back into a
     * static that survives [org.kysecurity.mail.security.AppRestart.relaunch]. Sealing on [clear]
     * makes the late write a no-op instead of a resurrection.
     */
    @Volatile
    private var sealed: Boolean = false

    init {
        ProcessState.register(this)
    }

    fun save(draft: CachedDraft) {
        if (sealed) return
        this.draft = draft.takeIf { it.hasContent() }
    }

    /**
     * Returns and clears — a restored draft is now owned by the screen that took it.
     *
     * Also unseals: a compose screen asking for the draft is a live session, and any callback left
     * over from the session that was wiped has long since been drained off the main looper (it was
     * queued strictly earlier than this Activity's `onCreate`).
     */
    fun take(): CachedDraft? {
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

data class CachedDraft(
    val to: String,
    val cc: String,
    val bcc: String,
    val subject: String,
    val bodyHtml: String,
    val attachments: List<OutgoingAttachment>,
    /** The Encrypt and Sign toggles. Carried here because the compose form is excluded from the
     *  saved-state Bundle (see `ComposeActivity.onCreate`), and a fold that silently reset Encrypt
     *  to its unchecked layout default would send in the clear a message the user had asked to
     *  encrypt. Not part of [hasContent]: a toggle with nothing typed is not a draft. */
    val encrypt: Boolean = false,
    val sign: Boolean = false,
) {
    /** An untouched compose screen is not worth restoring, and caching it would silently
     *  resurrect an empty draft over a later Reply's prefilled fields. */
    fun hasContent(): Boolean =
        to.isNotBlank() || cc.isNotBlank() || bcc.isNotBlank() ||
            subject.isNotBlank() || attachments.isNotEmpty() ||
            bodyHtml.isNotBlank()
}
