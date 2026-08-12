package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment

/**
 * Carries a forwarded message's attachments from [EmailDetailActivity] to [ComposeActivity].
 *
 * Not an Intent extra: attachments are base64 and capped at 25 MB total, while a Binder
 * transaction is limited to roughly 1 MB — putting them in the Intent throws
 * `TransactionTooLargeException` on any real attachment. Both Activities live in this process, so
 * a single-use handoff is both correct and cheaper than making Compose re-download what the detail
 * screen already has in hand.
 *
 * Single-use ([take] clears) so a later plain Compose cannot silently inherit the attachments of a
 * forward the user abandoned.
 */
object ForwardAttachmentHandoff : ProcessScopedState {
    @Volatile
    private var pending: List<OutgoingAttachment>? = null

    init {
        ProcessState.register(this)
    }

    override fun resetForNewSession() = clear()

    fun put(attachments: List<OutgoingAttachment>) {
        pending = attachments.takeIf { it.isNotEmpty() }
    }

    fun take(): List<OutgoingAttachment> {
        val current = pending
        pending = null
        return current.orEmpty()
    }

    fun clear() {
        pending = null
    }
}
