package com.urlxl.mail

import com.urlxl.mail.mail.OutgoingAttachment

/**
 * The in-progress composition, held for the life of the process so the app lock cannot destroy it.
 *
 * [com.urlxl.mail.security.LockedActivity] *finishes* a gated screen rather than layering the
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
object ComposeDraftCache {
    @Volatile
    private var draft: CachedDraft? = null

    fun save(draft: CachedDraft) {
        this.draft = draft.takeIf { it.hasContent() }
    }

    /** Returns and clears — a restored draft is now owned by the screen that took it. */
    fun take(): CachedDraft? {
        val current = draft
        draft = null
        return current
    }

    fun clear() {
        draft = null
    }
}

data class CachedDraft(
    val to: String,
    val cc: String,
    val bcc: String,
    val subject: String,
    val bodyHtml: String,
    val attachments: List<OutgoingAttachment>,
) {
    /** An untouched compose screen is not worth restoring, and caching it would silently
     *  resurrect an empty draft over a later Reply's prefilled fields. */
    fun hasContent(): Boolean =
        to.isNotBlank() || cc.isNotBlank() || bcc.isNotBlank() ||
            subject.isNotBlank() || attachments.isNotEmpty() ||
            bodyHtml.isNotBlank()
}
