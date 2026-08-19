package org.kysecurity.mail

import org.kysecurity.mail.mail.OutgoingAttachment

/** Not an Intent extra: attachment bytes exceed the ~1 MB Binder transaction limit. */
object ForwardAttachmentHandoff : ProcessScopedState {
    @Volatile
    private var pending: List<OutgoingAttachment>? = null

    init {
        ProcessState.register(this)
    }

    /** Zeroes rather than merely dropping. A session boundary is a wipe or an account switch, and
     *  dropped plaintext stays readable in a heap dump until the collector runs — the same reason
     *  [org.kysecurity.mail.security.EphemeralAttachmentBytes] overwrites. Only possible at all
     *  because these are now `ByteArray`s: the base64 `String` they used to be could not be. */
    override fun resetForNewSession() {
        pending?.forEach { it.wipe() }
        clear()
    }

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
