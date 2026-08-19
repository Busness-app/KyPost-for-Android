package org.kysecurity.mail.data

import androidx.room.Entity
import androidx.room.PrimaryKey

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
    // Cached so a client-protected message is not indistinguishable from one with an empty body.
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
) {
    /** Redacted: the preview and body are cached message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "EmailEntity(redacted)"
}
