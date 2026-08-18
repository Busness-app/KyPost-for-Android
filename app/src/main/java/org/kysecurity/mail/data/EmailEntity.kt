package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Local cache row for one message, populated by [org.kysecurity.mail.mail.RelayMailSource].
 * This is the UI's read model — relay reconciles delta responses into it (new/updated/removed,
 * Mobile_Mail_Relay.md Part 5) rather than re-fetching everything on each screen visit.
 */
@Entity(tableName = "emails")
data class EmailEntity(
    @PrimaryKey val messageId: String,
    val folder: String,
    val sender: String,
    val sentTo: String = "",
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val preview: String = "",
    val body: String? = null,
    val bodyMode: String = "",
    val label: String = "",
    val keywordsJson: String = "[]",
    val status: String = "unread",
    val atUtc: String? = null,
    val hasAttachments: Boolean = false,
    val sourceMode: String,
    // Persisted because the inbox list renders from this cache: without them a
    // client-protected message would come back from Room indistinguishable from
    // one with a genuinely empty body. The server keeps these flags across
    // delta "updated" entries, so caching them does not go stale.
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
) {
    /** Redacted: the preview and body are cached message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "EmailEntity(redacted)"
}
