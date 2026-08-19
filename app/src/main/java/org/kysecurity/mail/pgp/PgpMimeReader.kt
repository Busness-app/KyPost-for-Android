package org.kysecurity.mail.pgp

import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.util.Properties

/** Both kept: a message with only a plain part must not render as an empty page. */
internal data class DecryptedBody(
    val html: String?,
    val plain: String?,
    /** MIME mode paired with the selected body; never infer this from its characters. */
    val bodyMode: String = "",
    /** The real subject from the encrypted part's protected headers, when the sender used them.
     *  The outer envelope subject is a placeholder for KyPost-to-KyPost mail. */
    val protectedSubject: String?,
) {
    /** Redacted: every field is a decrypted message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "DecryptedBody(redacted)"
}

/** Returns null rather than throwing; unparsed bytes never reach a WebView. */
internal object PgpMimeReader {

    fun read(mime: ByteArray): DecryptedBody? = runCatching {
        val session = Session.getInstance(Properties())
        val message = MimeMessage(session, ByteArrayInputStream(mime))

        var html: String? = null
        var plain: String? = null

        fun walk(content: Any?) {
            if (content !is MimeMultipart) return
            for (i in 0 until content.count) {
                val part = content.getBodyPart(i)
                val body = runCatching { part.content }.getOrNull()
                when {
                    part.isMimeType("text/html") -> {
                        val s = body as? String
                        // A blank part is real content, but a later non-blank sibling must win.
                        if (s != null && (html == null || html!!.isBlank())) html = s
                    }
                    part.isMimeType("text/plain") -> {
                        val s = body as? String
                        if (s != null && (plain == null || plain!!.isBlank())) plain = s
                    }
                    body is MimeMultipart -> walk(body)
                }
            }
        }

        val hadContentTypeHeader = message.getHeader("Content-Type", null) != null
        val content = message.content
        when {
            message.isMimeType("text/html") -> html = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            message.isMimeType("text/plain") -> plain = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            else -> walk(content)
        }

        if (html == null && plain == null) return null
        DecryptedBody(
            html = html,
            plain = plain,
            bodyMode = if (html != null) "html" else "plain",
            protectedSubject = message.subject?.takeIf { it.isNotBlank() },
        )
    }.getOrNull()
}
