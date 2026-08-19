package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment

/** Not an Intent extra: base64 attachments exceed the ~1 MB Binder transaction limit. */
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
