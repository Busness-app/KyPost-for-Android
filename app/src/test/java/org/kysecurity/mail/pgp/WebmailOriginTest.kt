package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the guard on the webmail handoff, and the launch order it feeds.
 *
 * The handoff is the one place the app tells the user "this is your mail, sign in here", so
 * only URLs whose origin equals the paired server's are eligible; everything else is refused
 * outright rather than degraded to a browser launch.
 */
class WebmailOriginTest {

    private val server = "https://mail.example.com"

    @Test
    fun `accepts a url on the same origin`() {
        assertTrue(isFirstPartyWebmailUrl(server, "https://mail.example.com/read?message=5"))
    }

    @Test
    fun `accepts the server url with a trailing slash`() {
        assertTrue(isFirstPartyWebmailUrl("https://mail.example.com/", "https://mail.example.com/read"))
    }

    @Test
    fun `rejects a different host`() {
        assertFalse(isFirstPartyWebmailUrl(server, "https://evil.example.com/read?message=5"))
    }

    @Test
    fun `rejects a lookalike subdomain`() {
        assertFalse(isFirstPartyWebmailUrl(server, "https://mail.example.com.evil.test/read"))
    }

    @Test
    fun `rejects a different port`() {
        assertFalse(isFirstPartyWebmailUrl("https://mail.example.com:8443", "https://mail.example.com/read"))
    }

    @Test
    fun `rejects a downgrade to http`() {
        assertFalse(isFirstPartyWebmailUrl(server, "http://mail.example.com/read"))
    }

    @Test
    fun `rejects a non-http scheme`() {
        assertFalse(isFirstPartyWebmailUrl(server, "javascript:alert(1)"))
    }

    @Test
    fun `rejects a malformed candidate`() {
        assertFalse(isFirstPartyWebmailUrl(server, "not a url"))
    }

    @Test
    fun `rejects a blank candidate`() {
        assertFalse(isFirstPartyWebmailUrl(server, ""))
    }

    @Test
    fun `rejects a malformed server url`() {
        assertFalse(isFirstPartyWebmailUrl("not a url", "https://mail.example.com/read"))
    }

    /**
     * The order is the whole contract: a PWA attempt cannot be predicted, only tried, so the list
     * must lead with it and still hold a fallback for the (usual) case where it fails.
     */
    @Test
    fun `tries the pwa first, then any browser`() {
        assertEquals(
            listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER),
            webmailLaunchOrder(isFirstParty = true),
        )
    }

    /**
     * A Custom Tab renders inside KyPost's own task, where this app's FLAG_SECURE does not reach
     * the browser's window — so decrypted mail could appear in the KyPost Recents card. Every mode
     * that survives here launches into some other app's task. This is the regression test for that;
     * `WebmailLaunchMode` no longer has a CUSTOM_TAB entry to return, and re-adding one has to fail
     * here before it can ship.
     */
    @Test
    fun `never launches webmail inside this app's own task`() {
        assertEquals(
            listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER, WebmailLaunchMode.NONE),
            WebmailLaunchMode.entries,
        )
    }

    /** Refusal is an empty chain, so nothing is attempted at all — not a browser fallback, which
     *  would hide the programming error that produced a foreign URL. */
    @Test
    fun `refuses a url that is not first party`() {
        assertEquals(
            emptyList<WebmailLaunchMode>(),
            webmailLaunchOrder(isFirstParty = false),
        )
    }
}
