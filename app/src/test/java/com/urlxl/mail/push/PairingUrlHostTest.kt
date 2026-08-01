package com.urlxl.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pairing confirmation dialog is a trust prompt, and it used to render the raw `srv` string
 * straight from the deep link. A URL with userinfo reads as the trusted host on a wrapped dialog
 * while every request goes somewhere else — and `kypost://native-pair` is BROWSABLE, so any web
 * page can fire it.
 */
class PairingUrlHostTest {

    @Test
    fun rejectsUserinfoThatImpersonatesATrustedHost() {
        assertNull(pairingUrlHost("https://mail.trusted-corp.com@evil.tld/"))
        assertNull(pairingUrlHost("https://mail.trusted-corp.com:443@evil.tld/api"))
        assertNull(pairingUrlHost("https://user:pass@evil.tld"))
    }

    @Test
    fun acceptsOrdinaryHttpsUrlsAndReturnsTheHostToDisplay() {
        assertEquals("relay.example.com", pairingUrlHost("https://relay.example.com"))
        assertEquals("relay.example.com", pairingUrlHost("https://relay.example.com/"))
        // A path is fine: `reg` legitimately carries one, and a path cannot change the host.
        assertEquals("relay.example.com", pairingUrlHost("https://relay.example.com/api/notifications/native/register"))
        assertEquals("relay.example.com", pairingUrlHost("https://relay.example.com:8443/kypost"))
    }

    @Test
    fun rejectsNonHttpsAndUnparseableUrls() {
        assertNull(pairingUrlHost("http://relay.example.com"))
        assertNull(pairingUrlHost("kypost://native-pair"))
        assertNull(pairingUrlHost("not a url"))
        assertNull(pairingUrlHost(""))
    }

    @Test
    fun pairingEndpoint_rechecksPersistedServerUrlBeforeBuildingCredentialDestination() {
        assertEquals(
            "https://relay.example.com/api/contacts/sync",
            pairingEndpoint("https://relay.example.com", "/api/contacts/sync")?.toString(),
        )
        assertNull(pairingEndpoint("http://relay.example.com", "/api/contacts/sync"))
        assertNull(pairingEndpoint("https://trusted.example@evil.example", "/api/contacts/sync"))
    }

    @Test
    fun sameOrigin_requiresTheSameEffectivePort() {
        assertTrue(sameOrigin("https://relay.example.com:8443/api", "https://relay.example.com:8443"))
        assertTrue(!sameOrigin("https://relay.example.com:8443/api", "https://relay.example.com"))
    }

    @Test
    fun deepLinkParserRefusesAUserinfoServerUrl() {
        val link = "kypost://native-pair?sub=s1&pt=t1&srv=" +
            java.net.URLEncoder.encode("https://mail.trusted-corp.com@evil.tld/", "UTF-8")

        val result = NativePairingDeepLinkParser.parse(link)

        assertTrue("expected Error, got $result", result is PairingParseResult.Error)
    }

    @Test
    fun deepLinkParserStillAcceptsAnHonestPairingLink() {
        val link = "kypost://native-pair?sub=s1&pt=t1&srv=" +
            java.net.URLEncoder.encode("https://relay.example.com", "UTF-8")

        val result = NativePairingDeepLinkParser.parse(link)

        assertTrue("expected Success, got $result", result is PairingParseResult.Success)
        assertEquals("https://relay.example.com", (result as PairingParseResult.Success).pairing.serverUrl)
    }

    /** sameOrigin is also reached for pairings persisted by an older build, which is exactly where
     *  a userinfo URL saved before this check existed would still be sitting. */
    @Test
    fun sameOriginRefusesUserinfoOnEitherSide() {
        assertTrue(sameOrigin("https://relay.example.com/api", "https://relay.example.com"))
        assertTrue(!sameOrigin("https://good@relay.example.com/api", "https://relay.example.com"))
        assertTrue(!sameOrigin("https://relay.example.com/api", "https://good@relay.example.com"))
    }
}
