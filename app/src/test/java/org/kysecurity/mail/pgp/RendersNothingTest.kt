package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The blank-screen case.
 *
 * `renderPgpBar`'s own KDoc says "Silence here is what the old build did, and it read as 'this email
 * is blank'". That was fixed for every encrypted state and left open for [PgpMessageState.NONE],
 * which is exactly where an encrypted-but-unwarmed message lands: `pgpEncrypted` is `omitempty`
 * server-side and defaults to false here, so it arrives flagged as ordinary mail with no body.
 */
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

    /**
     * The preview is the fallback the detail view already renders for [PgpMessageState.NONE], so a
     * message carrying one is not blank and must not be labelled as such.
     */
    @Test
    fun aPreviewIsSomethingToShow() {
        assertFalse(rendersNothing(PgpMessageState.NONE, body = null, preview = "lunch tomorrow?"))
    }

    /**
     * Every other state already puts its own notice on screen, and saying "nothing to show" beside
     * "this message is end-to-end encrypted" would contradict it. CLIENT_PROTECTED in particular
     * renders an empty body **on purpose**.
     */
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
