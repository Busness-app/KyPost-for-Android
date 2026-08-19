package org.kysecurity.mail.pgp

import java.security.SecureRandom
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** Hand-assembled, not `jakarta.mail`: the goal is the exact bytes the relay's validator takes. */

/** One outgoing attachment, already base64-encoded — the form `OutgoingAttachment` already holds. */
internal data class OutgoingMimeAttachment(
    val name: String,
    val mimeType: String,
    val dataBase64: String,
)

/** No `bcc` field on purpose: the relay refuses a `Bcc` header and each BCC gets its own send. */
internal data class OutgoingEnvelope(
    val from: String,
    val to: List<String>,
    val cc: List<String>,
    val date: String,
)

/** Matches `pgpmail.OuterPlaceholderSubject` so both send paths look identical on the wire. */
internal const val OUTER_PLACEHOLDER_SUBJECT = "[Encrypted] Email Sent by KyPost"

/** `/api/mail/send-pgp` relays these bytes verbatim, so the header set is fixed and closed. */
internal fun wrapAsPgpMime(
    envelope: OutgoingEnvelope,
    armoredMessage: String,
    boundaryToken: () -> String = ::randomBoundaryToken,
): String {
    val boundary = "kypost-pgp-boundary-${boundaryToken()}"
    val lines = mutableListOf<String>()
    lines += "From: ${sanitizeHeaderValue(envelope.from)}"
    lines += "To: ${joinAddresses(envelope.to)}"
    val cc = joinAddresses(envelope.cc)
    if (cc.isNotEmpty()) lines += "Cc: $cc"
    // The real subject is inside the ciphertext as a protected header; this is the same placeholder
    // the server-side path uses.
    lines += "Subject: $OUTER_PLACEHOLDER_SUBJECT"
    lines += "Date: ${sanitizeHeaderValue(envelope.date)}"
    lines += "MIME-Version: 1.0"
    lines += "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"$boundary\""
    lines += ""
    lines += "This is an OpenPGP/MIME encrypted message (RFC 3156)."
    lines += "--$boundary"
    lines += "Content-Type: application/pgp-encrypted"
    lines += "Content-Description: PGP/MIME version identification"
    lines += ""
    lines += "Version: 1"
    lines += ""
    lines += "--$boundary"
    lines += "Content-Type: application/octet-stream; name=\"encrypted.asc\""
    lines += "Content-Description: OpenPGP encrypted message"
    lines += "Content-Disposition: inline; filename=\"encrypted.asc\""
    lines += ""
    lines += armoredMessage.trim()
    lines += ""
    lines += "--$boundary--"
    lines += ""
    return lines.joinToString(CRLF)
}

private fun joinAddresses(addresses: List<String>): String =
    addresses.map(::sanitizeHeaderValue).filter { it.isNotEmpty() }.joinToString(", ")

/** Flattens CR/LF so a header value cannot inject additional headers. */
internal fun sanitizeHeaderValue(value: String): String =
    value.replace(CR_OR_LF, " ").trim()

/** The outer Subject is a placeholder, so this is the only place the real one travels. */
internal fun buildProtectedContent(
    contentType: String,
    body: String,
    subject: String,
    attachments: List<OutgoingMimeAttachment> = emptyList(),
    boundaryToken: () -> String = ::randomBoundaryToken,
): String {
    val clean = sanitizeHeaderValue(subject)
    val boundary = "kypost-protected-${boundaryToken()}"
    val lines = mutableListOf<String>()
    if (clean.isNotEmpty()) lines += "Subject: $clean"
    lines += "Content-Type: multipart/mixed; boundary=\"$boundary\"; protected-headers=\"v1\""
    lines += ""
    // The memoryhole convention: Thunderbird, Mutt and K-9 read the subject from this part.
    if (clean.isNotEmpty()) {
        lines += "--$boundary"
        lines += "Content-Type: text/rfc822-headers; protected-headers=\"v1\""
        lines += "Content-Disposition: inline"
        lines += ""
        lines += "Subject: $clean"
        lines += ""
    }
    lines += "--$boundary"
    lines += "Content-Type: $contentType"
    lines += ""
    lines += body
    lines += ""
    attachments.forEach { attachment ->
        val name = sanitizeHeaderValue(attachment.name).replace("\"", "")
        lines += "--$boundary"
        lines += "Content-Type: ${sanitizeHeaderValue(attachment.mimeType)}; name=\"$name\""
        lines += "Content-Transfer-Encoding: base64"
        lines += "Content-Disposition: attachment; filename=\"$name\""
        lines += ""
        // The app stores attachment bytes NO_WRAP, i.e. one unbroken line. RFC 2045 caps an encoded
        // line at 76 characters, and a parser that enforces it would otherwise reject the part.
        lines += wrapBase64(attachment.dataBase64)
        lines += ""
    }
    lines += "--$boundary--"
    lines += ""
    return lines.joinToString(CRLF)
}

private fun wrapBase64(data: String): String =
    data.filterNot { it == '\r' || it == '\n' }
        .chunked(BASE64_LINE_LENGTH)
        .joinToString(CRLF)

/** Do NOT swap for `ofPattern(...)`: it renders through the default locale, e.g. "Ağu" on tr_TR. */
internal fun rfc5322Date(at: OffsetDateTime): String =
    DateTimeFormatter.RFC_1123_DATE_TIME.format(at.withOffsetSameInstant(ZoneOffset.UTC))

internal fun randomBoundaryToken(): String {
    val bytes = ByteArray(12).also { SecureRandom().nextBytes(it) }
    return bytes.joinToString("") { "%02x".format(it) }
}

private const val CRLF = "\r\n"
private const val BASE64_LINE_LENGTH = 76
private val CR_OR_LF = Regex("[\\r\\n]+")
