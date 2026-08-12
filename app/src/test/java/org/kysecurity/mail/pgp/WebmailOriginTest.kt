package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the guard that decides whether a URL may be opened in a Custom Tab.
 *
 * A Custom Tab renders inside this app's task, so opening an attacker-chosen URL in one would
 * lend the app's trust to a phishing page. Only URLs whose origin equals the paired server's
 * are eligible; everything else falls back to an external browser or is refused.
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
    fun `tries the pwa first, then a custom tab, then any browser`() {
        assertEquals(
            listOf(
                WebmailLaunchMode.NATIVE_APP,
                WebmailLaunchMode.CUSTOM_TAB,
                WebmailLaunchMode.EXTERNAL_BROWSER,
            ),
            webmailLaunchOrder(isFirstParty = true, customTabsPackage = "com.android.chrome"),
        )
    }

    /** No Custom Tabs-capable browser: the tab is dropped from the chain, not the PWA attempt. */
    @Test
    fun `drops the custom tab when no capable browser is installed`() {
        assertEquals(
            listOf(WebmailLaunchMode.NATIVE_APP, WebmailLaunchMode.EXTERNAL_BROWSER),
            webmailLaunchOrder(isFirstParty = true, customTabsPackage = null),
        )
    }

    /** Refusal is an empty chain, so nothing is attempted at all — not a browser fallback, which
     *  would hide the programming error that produced a foreign URL. */
    @Test
    fun `refuses a url that is not first party even when a custom tab is available`() {
        assertEquals(
            emptyList<WebmailLaunchMode>(),
            webmailLaunchOrder(isFirstParty = false, customTabsPackage = "com.android.chrome"),
        )
    }

    @Test
    fun `refuses a url that is not first party when no browser is available either`() {
        assertEquals(
            emptyList<WebmailLaunchMode>(),
            webmailLaunchOrder(isFirstParty = false, customTabsPackage = null),
        )
    }
}
