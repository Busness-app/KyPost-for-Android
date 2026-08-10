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
    /** MIME mode paired with the selected body; never infer this from its characters. */
    val bodyMode: String = "",
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
 * not rejected, they're accepted as a default `text/plain` message with an empty-string body — RFC
 * 2045's default content type, not something parsed from the input. That default is indistinguishable
 * from a real, empty `text/plain` body by content alone, so the blank check at the top level only fires
 * when [MimeMessage.getHeader] shows no `Content-Type` header was actually present: `hadContentTypeHeader
 * == false` means the empty string came from the RFC default, not from a parsed header, and only then is
 * blank treated as absent. When a `Content-Type` header *was* parsed, an empty body is real — a
 * "no body, attachment only" message is a legitimate compose pattern — so it is kept as `""`, not
 * collapsed to `null`. Inside [walk], every part reached was found via genuine multipart boundary
 * parsing, so a blank part there is always real content and is never discarded outright — but it does
 * not get to keep a slot a later sibling could fill with something non-blank. The first non-blank
 * `text/html` (or `text/plain`) part wins; a blank part is only kept if nothing better ever turns up,
 * so an all-blank multipart still ends as `""` rather than `null`, and a blank-then-real pair never
 * silently drops the real content behind an already-filled slot.
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
                    part.isMimeType("text/html") -> {
                        val s = body as? String
                        // A blank part is real content — a multipart whose only text part is empty
                        // must yield "" and not null. But it must not lock the slot: a later
                        // sibling with actual content has to win, or it is silently dropped and
                        // the message renders blank with no error.
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
