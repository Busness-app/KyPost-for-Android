package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PgpMimeReaderTest {

    private fun read(mime: String) = PgpMimeReader.read(mime.toByteArray(Charsets.UTF_8))

    @Test
    fun readsAPlainTextOnlyMessage() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8

            Just text.
            """.trimIndent(),
        )

        assertEquals("Just text.", body?.plain?.trim())
        assertNull(body?.html)
    }

    @Test
    fun prefersHtmlFromMultipartAlternative() {
        val body = read(
            """
            Content-Type: multipart/alternative; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            fallback text
            --b1
            Content-Type: text/html; charset=utf-8

            <p>rich text</p>
            --b1--
            """.trimIndent(),
        )

        assertTrue("expected the html part", body?.html?.contains("rich text") == true)
        assertTrue("expected the plain part kept too", body?.plain?.contains("fallback text") == true)
    }

    @Test
    fun recoversAProtectedSubject() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8
            Subject: The real subject

            body
            """.trimIndent(),
        )

        assertEquals("The real subject", body?.protectedSubject)
    }

    @Test
    fun returnsNullForBytesThatAreNotMime() {
        // Fails closed: the caller shows "could not decrypt" rather than rendering garbage
        // into a WebView.
        assertNull(PgpMimeReader.read(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun distinguishesAGenuinelyEmptyBodyFromGarbage() {
        // An explicit Content-Type header was parsed here, so the empty body is real content (e.g. an
        // "attachment only, no body" compose) — not the RFC 2045 default angus.mail falls back to for
        // non-MIME input. It must not be collapsed to null like the garbage-bytes case below.
        val mime = "Content-Type: text/plain; charset=utf-8\n\n"

        val body = PgpMimeReader.read(mime.toByteArray(Charsets.UTF_8))

        assertEquals("", body?.plain)
        assertNull(body?.html)
        assertNull(PgpMimeReader.read(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun recursesIntoNestedMultiparts() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="outer"

            --outer
            Content-Type: multipart/alternative; boundary="inner"

            --inner
            Content-Type: text/plain; charset=utf-8

            nested fallback text
            --inner
            Content-Type: text/html; charset=utf-8

            <p>nested rich text</p>
            --inner--
            --outer--
            """.trimIndent(),
        )

        assertTrue("expected the nested html part", body?.html?.contains("nested rich text") == true)
        assertTrue("expected the nested plain part", body?.plain?.contains("nested fallback text") == true)
    }

    @Test
    fun walkPrefersFirstNonBlankPartOverAnEarlierBlankSibling() {
        // A blank part must not lock the slot: if a later sibling of the same subtype carries real
        // content, that content has to win. Otherwise it is silently dropped and the message renders
        // blank with no error shown to the user.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            --b1
            Content-Type: text/html; charset=utf-8

            <p>real content</p>
            --b1--
            """.trimIndent(),
        )

        assertEquals("<p>real content</p>", body?.html?.trim())
    }

    @Test
    fun walkKeepsRealContentWhenALaterSiblingOfTheSameSubtypeIsBlank() {
        // Once the slot holds real content, a later blank sibling must not overwrite it.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            <p>real content</p>
            --b1
            Content-Type: text/html; charset=utf-8

            --b1--
            """.trimIndent(),
        )

        assertEquals("<p>real content</p>", body?.html?.trim())
    }

    @Test
    fun walkKeepsAnAllBlankMultipartAsEmptyStringNotNull() {
        // A blank part is still real content when nothing better ever turns up.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            --b1--
            """.trimIndent(),
        )

        assertEquals("", body?.html)
        assertNull(body?.plain)
    }
}
