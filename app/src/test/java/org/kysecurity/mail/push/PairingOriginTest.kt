package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingOriginTest {

    private fun link(srv: String, reg: String? = null): String {
        val encodedSrv = java.net.URLEncoder.encode(srv, "UTF-8")
        val regPart = reg?.let { "&reg=" + java.net.URLEncoder.encode(it, "UTF-8") }.orEmpty()
        return "kypost://native-pair?sub=subscriber-123&srv=$encodedSrv$regPart&pt=token"
    }

    @Test
    fun parse_rejectsRegOnADifferentHost() {
        val result = NativePairingDeepLinkParser.parse(
            link(srv = "https://mail.example.com", reg = "https://evil.example/register"),
        )

        assertTrue(result is PairingParseResult.Error)
        assertTrue((result as PairingParseResult.Error).reason.contains("same server"))
    }

    @Test
    fun parse_rejectsRegOnADifferentPort() {
        val result = NativePairingDeepLinkParser.parse(
            link(srv = "https://mail.example.com", reg = "https://mail.example.com:8443/register"),
        )

        assertTrue(result is PairingParseResult.Error)
    }

    @Test
    fun parse_rejectsRegOnALookalikeSubdomain() {
        val result = NativePairingDeepLinkParser.parse(
            link(srv = "https://mail.example.com", reg = "https://mail.example.com.evil.test/register"),
        )

        assertTrue(result is PairingParseResult.Error)
    }

    @Test
    fun parse_acceptsRegOnTheSameOrigin() {
        val result = NativePairingDeepLinkParser.parse(
            link(srv = "https://mail.example.com", reg = "https://mail.example.com/api/register"),
        )

        assertTrue(result is PairingParseResult.Success)
        assertEquals(
            "https://mail.example.com/api/register",
            (result as PairingParseResult.Success).pairing.registrationUrl,
        )
    }

    @Test
    fun parse_acceptsAnExplicitDefaultPortAsTheSameOrigin() {
        val result = NativePairingDeepLinkParser.parse(
            link(srv = "https://mail.example.com", reg = "https://mail.example.com:443/api/register"),
        )

        assertTrue(result is PairingParseResult.Success)
    }

    @Test
    fun parse_stillRejectsPlainHttp() {
        assertTrue(NativePairingDeepLinkParser.parse(link(srv = "http://mail.example.com")) is PairingParseResult.Error)
    }

    @Test
    fun resolve_ignoresACrossOriginRegAndDerivesFromSrv() {
        val result = NativeRegistrationEndpointResolver.resolve(
            qrReg = "https://evil.example/register",
            qrServerUrl = "https://mail.example.com",
        )

        val resolved = result as NativeRegistrationEndpointResolver.Resolution.Resolved
        assertEquals("https://mail.example.com/api/notifications/native/register", resolved.registrationUrl)
    }

    @Test
    fun resolve_refusesARegUrlWithNoServerUrlToValidateItAgainst() {
        val result = NativeRegistrationEndpointResolver.resolve(
            qrReg = "https://evil.example/register",
            qrServerUrl = null,
        )

        assertTrue(result is NativeRegistrationEndpointResolver.Resolution.MissingServerUrl)
    }
}
