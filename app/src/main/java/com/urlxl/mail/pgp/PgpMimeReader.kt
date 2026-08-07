package com.urlxl.mail.pgp

import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.util.Properties

/**
 * The readable parts of a decrypted PGP/MIME message.
 *
 * Both [html] and [plain] are kept rather than collapsing to one: the caller decides what to put in
 * the WebView, and a message with only a plain part must not render as an empty page.
 */
internal data class DecryptedBody(
    val html: String?,
    val plain: String?,
    /** The real subject from the encrypted part's protected headers, when the sender used them.
     *  The outer envelope subject is a placeholder for KyPost-to-KyPost mail. */
    val protectedSubject: String?,
)

/**
 * Parses decrypted PGP/MIME bytes with `angus.mail`, with **no Android imports**.
 *
 * Note this is `angus.mail`'s first use in this app — it has been a declared dependency, imported by
 * nothing, so "already on the classpath" was never the same as "known to work here".
 *
 * Returns null rather than throwing on anything unparseable. The caller renders an exit-table row;
 * putting unparsed bytes into a WebView is not a degradation this accepts.
 *
 * `angus.mail`'s parser is lenient: bytes with no recognizable MIME headers (e.g. random binary) are
 * not rejected, they're accepted as a default `text/plain` message with an empty-string body. So a
 * blank/empty part is treated the same as "no part found" below, rather than as real content — that's
 * what lets [read] fail closed on genuinely non-MIME input instead of returning an empty [DecryptedBody].
 */
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
                    part.isMimeType("text/html") -> if (html == null) html = (body as? String)?.takeIf { it.isNotBlank() }
                    part.isMimeType("text/plain") -> if (plain == null) plain = (body as? String)?.takeIf { it.isNotBlank() }
                    body is MimeMultipart -> walk(body)
                }
            }
        }

        val content = message.content
        when {
            message.isMimeType("text/html") -> html = (content as? String)?.takeIf { it.isNotBlank() }
            message.isMimeType("text/plain") -> plain = (content as? String)?.takeIf { it.isNotBlank() }
            else -> walk(content)
        }

        if (html == null && plain == null) return null
        DecryptedBody(
            html = html,
            plain = plain,
            protectedSubject = message.subject?.takeIf { it.isNotBlank() },
        )
    }.getOrNull()
}
