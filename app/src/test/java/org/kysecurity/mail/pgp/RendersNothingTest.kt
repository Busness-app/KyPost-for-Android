package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** `pgpEncrypted` is `omitempty` server-side, so an unwarmed encrypted message arrives as NONE. */
class RendersNothingTest {

    @Test
    fun aMessageWithNoBodyNoPreviewAndNoNoticeRendersNothing() {
        assertTrue(rendersNothing(PgpMessageState.NONE, body = null, preview = ""))
    }

    /** The empty-string body is the same case: the server had a row for it and no content. */
    @Test
    fun anEmptyBodyCountsAsNothing() {
        assertTrue(rendersNothing(PgpMessageState.NONE, body = "", preview = "   "))
    }

    @Test
    fun aBodyIsSomethingToShow() {
        assertFalse(rendersNothing(PgpMessageState.NONE, body = "<p>hello</p>", preview = ""))
    }

    /** The preview is the fallback the detail view already renders for [PgpMessageState.NONE]. */
    @Test
    fun aPreviewIsSomethingToShow() {
        assertFalse(rendersNothing(PgpMessageState.NONE, body = null, preview = "lunch tomorrow?"))
    }

    /** CLIENT_PROTECTED renders an empty body on purpose; every state here puts its own notice up. */
    @Test
    fun aStateThatExplainsItselfIsNotBlank() {
        listOf(
            PgpMessageState.CLIENT_PROTECTED,
            PgpMessageState.DECRYPT_FAILED,
            PgpMessageState.DECRYPTED_BY_SERVER,
            PgpMessageState.BODY_UNAVAILABLE,
        ).forEach {
            assertFalse("$it already explains itself", rendersNothing(it, body = null, preview = ""))
        }
    }
}
