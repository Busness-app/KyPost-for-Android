package com.urlxl.mail.pgp

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
}
