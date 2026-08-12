package org.kysecurity.mail.pgp

import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Base64
import java.util.Locale
import java.util.Properties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [PgpMimeReader] is the oracle here, exactly as [PgpDecryptor] is for [PgpEncryptorTest].
 *
 * Using an independent parser — `angus.mail`, which this writer does not use — to validate what the
 * writer emits is strictly stronger than round-tripping through one library's own encoder and
 * decoder, which can agree on a shape no other MUA accepts.
 */
class PgpMimeWriterTest {

    /**
     * The real subject travels inside the ciphertext as a protected header, and the reader lifts it
     * back out. If this breaks, every KyPost-to-KyPost message displays the outer placeholder
     * ("[Encrypted] Email Sent by KyPost") instead of its actual subject.
     */
    @Test
    fun protectedContentParsesBackThroughPgpMimeReader() {
        val content = buildProtectedContent(
            contentType = "text/html; charset=utf-8",
            body = "<p>Hello from the writer.</p>",
            subject = "Lunch on Thursday",
        )

        val parsed = requireNotNull(PgpMimeReader.read(content.toByteArray(Charsets.UTF_8)))

        assertEquals("Lunch on Thursday", parsed.protectedSubject)
        assertEquals("<p>Hello from the writer.</p>", parsed.html?.trim())
    }

    /**
     * The memoryhole / draft-ietf-lamps-header-protection convention: the real Subject is repeated
     * in a `text/rfc822-headers` part so other clients can find it.
     *
     * Without this part the subject is still readable by KyPost — which reads the top-level header —
     * but Thunderbird, Mutt and K-9 show the placeholder, and the server's own
     * `ExtractProtectedSubject` is written to accept exactly this shape.
     */
    @Test
    fun repeatsTheSubjectInAnRfc822HeadersPart() {
        val content = buildProtectedContent(
            contentType = "text/html; charset=utf-8",
            body = "<p>Body</p>",
            subject = "Lunch on Thursday",
        )

        val marker = content.indexOf("Content-Type: text/rfc822-headers; protected-headers=\"v1\"")
        assertTrue("a text/rfc822-headers part must be present", marker >= 0)
        assertTrue(
            "that part must carry the real subject",
            content.substring(marker).startsWith(
                "Content-Type: text/rfc822-headers; protected-headers=\"v1\"\r\n" +
                    "Content-Disposition: inline\r\n\r\nSubject: Lunch on Thursday",
            ),
        )
    }

    /**
     * Mirrors the relay's own `validatePGPMimeDeliveryShape` rule for rule.
     *
     * The server relays these bytes verbatim over SMTP and synthesizes nothing, so anything missing
     * here is simply absent from the delivered mail — and anything forbidden gets the whole send
     * rejected with a plain-text 400 after the ciphertext was already built.
     */
    @Test
    fun envelopeSatisfiesTheRelayDeliveryValidator() {
        val mime = wrapAsPgpMime(
            envelope = OutgoingEnvelope(
                from = "me@example.invalid",
                to = listOf("alice@example.invalid"),
                cc = listOf("bob@example.invalid"),
                date = "Mon, 11 Aug 2026 10:00:00 +0000",
            ),
            armoredMessage = "-----BEGIN PGP MESSAGE-----\n\nZm9v\n-----END PGP MESSAGE-----",
        )

        val split = mime.indexOf("\r\n\r\n")
        assertTrue("delivery must split into headers and body on a blank line", split > 0)
        val headers = mime.substring(0, split)

        listOf("From:", "To:", "Subject:", "Date:").forEach {
            assertTrue("required header $it missing", headers.lineSequence().any { l -> l.startsWith(it) })
        }
        assertEquals(
            "exactly one From header",
            1,
            headers.lineSequence().count { it.startsWith("From:") },
        )
        listOf("Received:", "Authentication-Results:", "Return-Path:", "Bcc:").forEach {
            assertTrue(
                "forbidden header $it must never be emitted",
                headers.lineSequence().none { l -> l.startsWith(it) },
            )
        }
        assertTrue(
            "RFC 3156 content type",
            headers.contains("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\""),
        )
        assertTrue("body must carry the armor marker", mime.contains("-----BEGIN PGP MESSAGE-----"))
        assertTrue(
            "the outer subject is a fixed placeholder — the real one is inside the ciphertext",
            headers.lineSequence().any { it == "Subject: $OUTER_PLACEHOLDER_SUBJECT" },
        )
    }

    /**
     * The whole outbound path composed: protect the headers, encrypt and sign, wrap as PGP/MIME —
     * then take it apart the way a recipient does.
     *
     * The leak assertion is the point. The real subject must appear nowhere in the delivery's
     * cleartext; if the placeholder is ever dropped, every encrypted message advertises its subject
     * to anyone who can see the envelope, and no unit test of either half would notice.
     */
    @Test
    fun aCompleteDeliveryRoundTripsAndLeaksNothingInCleartext() {
        val subject = "Quarterly numbers, confidential"
        val body = "<p>Revenue is up.</p>"

        val protectedContent = buildProtectedContent(
            contentType = "text/html; charset=utf-8",
            body = body,
            subject = subject,
        )
        val encrypted = PgpEncryptor.encrypt(
            plaintext = protectedContent.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = TestPgpPrivateKey.ARMORED_PRIVATE,
        ) as EncryptResult.Ok

        val delivery = wrapAsPgpMime(
            envelope = OutgoingEnvelope(
                from = "me@example.invalid",
                to = listOf("alice@example.invalid"),
                cc = emptyList(),
                date = "Mon, 11 Aug 2026 10:00:00 +0000",
            ),
            armoredMessage = encrypted.armored,
        )

        assertFalse("the real subject must never appear in cleartext", delivery.contains(subject))
        assertFalse("nor must the body", delivery.contains("Revenue is up"))

        val end = "-----END PGP MESSAGE-----"
        val armor = delivery.substring(
            delivery.indexOf("-----BEGIN PGP MESSAGE-----"),
            delivery.indexOf(end) + end.length,
        )
        val decrypted = PgpDecryptor.decrypt(
            armoredPrivateKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            armoredMessage = armor,
            signerPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertTrue("the recipient must see a valid signature", decrypted.signature.valid)
        val parsed = requireNotNull(PgpMimeReader.read(decrypted.plaintext))
        assertEquals(subject, parsed.protectedSubject)
        assertEquals(body, parsed.html?.trim())
    }

    /**
     * The `Date` header must be ASCII whatever the device's locale.
     *
     * This passes today without any locale pinning — `RFC_1123_DATE_TIME` hardcodes the English
     * abbreviations RFC 1123 mandates, so it is already locale-independent. The test exists for the
     * refactor that replaces it with `ofPattern("EEE, dd MMM yyyy HH:mm:ss Z")`, which looks
     * equivalent, renders through the default locale, and emits "Sal, 11 Ağu 2026" on a Turkish
     * device. That is a bug that never shows up in development and always shows up for some users.
     */
    @Test
    fun dateIsAsciiUnderANonEnglishDefaultLocale() {
        val original = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))
            assertEquals(
                "Tue, 11 Aug 2026 10:00:00 GMT",
                rfc5322Date(OffsetDateTime.of(2026, 8, 11, 10, 0, 0, 0, ZoneOffset.UTC)),
            )
        } finally {
            Locale.setDefault(original)
        }
    }

    @Test
    fun ccHeaderIsOmittedWhenEmpty() {
        val mime = wrapAsPgpMime(
            envelope = OutgoingEnvelope(
                from = "me@example.invalid",
                to = listOf("alice@example.invalid"),
                cc = emptyList(),
                date = "Mon, 11 Aug 2026 10:00:00 +0000",
            ),
            armoredMessage = "-----BEGIN PGP MESSAGE-----\n\nZm9v\n-----END PGP MESSAGE-----",
        )

        assertTrue(
            "an empty Cc must be omitted, not emitted blank",
            mime.lineSequence().none { it.startsWith("Cc:") },
        )
    }

    /**
     * Attachments ride inside the ciphertext, decoded by an independent parser here.
     *
     * The browser client has no attachment support on this path, but this app's compose screen has
     * an attach button — so dropping them silently would send a message the user believes carried a
     * file.
     */
    @Test
    fun attachmentSurvivesInsideTheProtectedContent() {
        val payload = "hello attachment\n"
        val content = buildProtectedContent(
            contentType = "text/html; charset=utf-8",
            body = "<p>See attached.</p>",
            subject = "With attachment",
            attachments = listOf(
                OutgoingMimeAttachment(
                    name = "notes.txt",
                    mimeType = "text/plain",
                    dataBase64 = Base64.getEncoder().encodeToString(payload.toByteArray(Charsets.UTF_8)),
                ),
            ),
        )

        val message = MimeMessage(
            Session.getInstance(Properties()),
            ByteArrayInputStream(content.toByteArray(Charsets.UTF_8)),
        )
        val multipart = message.content as MimeMultipart
        val attachment = (0 until multipart.count)
            .map { multipart.getBodyPart(it) }
            .single { it.fileName == "notes.txt" }

        // inputStream yields the decoded bytes whatever the part's type, where `content` would hand
        // back an already-stringified body for a text/* part.
        assertEquals(payload, attachment.inputStream.readBytes().toString(Charsets.UTF_8))
        assertEquals(
            "the body must still be readable alongside the attachment",
            "<p>See attached.</p>",
            requireNotNull(PgpMimeReader.read(content.toByteArray(Charsets.UTF_8))).html?.trim(),
        )
    }

    /** A subject is user input and lands in a header the relay forwards verbatim. A newline in it
     *  would otherwise inject arbitrary headers — `Bcc:` among them. */
    @Test
    fun headerInjectionViaSubjectIsFlattened() {
        val content = buildProtectedContent(
            contentType = "text/html; charset=utf-8",
            body = "<p>Body</p>",
            subject = "Innocent\r\nBcc: eve@evil.invalid",
        )

        assertEquals(
            "Innocent Bcc: eve@evil.invalid",
            requireNotNull(PgpMimeReader.read(content.toByteArray(Charsets.UTF_8))).protectedSubject,
        )
    }
}
