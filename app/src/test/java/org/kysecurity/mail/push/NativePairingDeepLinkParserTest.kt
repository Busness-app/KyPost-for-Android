package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativePairingDeepLinkParserTest {

    @Test
    fun parse_validDeepLink_extractsRequiredParams() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&srv=https%3A%2F%2Fserver.example.com" +
                "&reg=https%3A%2F%2Fserver.example.com%2Fapi%2Fnotifications%2Fnative%2Fregister&pt=short-lived-token",
            nowEpochMs = 123L,
        )

        assertTrue(result is PairingParseResult.Success)
        val pairing = (result as PairingParseResult.Success).pairing
        assertEquals("subscriber-123", pairing.subscriberId)
        assertEquals("https://server.example.com", pairing.serverUrl)
        assertEquals("https://server.example.com/api/notifications/native/register", pairing.registrationUrl)
        assertEquals("short-lived-token", pairing.pairingToken)
        assertEquals(null, pairing.deviceId)
        assertEquals(null, pairing.deviceSecret)
        assertEquals(123L, pairing.pairedAtEpochMs)
    }

    @Test
    fun parse_ignoresLegacyHashParamIfPresent() {
        // A stale cached QR image from before the per-device-secret migration may still carry a
        // hash= param; it must simply be ignored, not rejected, since it's harmless and the
        // pairingToken alone is what actually gates registration.
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&hash=stale-hash&srv=https%3A%2F%2Fserver.example.com&pt=token",
        )

        assertTrue(result is PairingParseResult.Success)
        val pairing = (result as PairingParseResult.Success).pairing
        assertEquals(null, pairing.deviceSecret)
    }

    @Test
    fun parse_missingReg_leavesRegistrationUrlBlank() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&srv=https%3A%2F%2Fserver.example.com&pt=token",
        )

        val pairing = (result as PairingParseResult.Success).pairing
        assertEquals("", pairing.registrationUrl)
    }

    @Test
    fun parse_missingPairingToken_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&srv=https%3A%2F%2Fserver.example.com",
        )

        assertTrue(result is PairingParseResult.Error)
        assertEquals("Missing pairing token", (result as PairingParseResult.Error).reason)
    }

    @Test
    fun parse_missingServerUrl_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&pt=token",
        )

        assertTrue(result is PairingParseResult.Error)
        assertEquals("Missing server URL", (result as PairingParseResult.Error).reason)
    }

    @Test
    fun parse_legacyNovuPairScheme_isRejected() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://novu-pair?sub=a&srv=https%3A%2F%2Fserver.example.com&pt=c",
        )

        assertTrue(result is PairingParseResult.Error)
    }

    @Test
    fun parse_invalidHost_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://other-host?sub=a&srv=https%3A%2F%2Fserver.example.com&pt=c",
        )

        assertTrue(result is PairingParseResult.Error)
    }

    @Test
    fun parse_httpServerUrl_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=a&srv=http%3A%2F%2Fserver.example.com&pt=c",
        )

        assertTrue(result is PairingParseResult.Error)
        assertEquals("Server URL must use https", (result as PairingParseResult.Error).reason)
    }

    @Test
    fun parse_httpRegistrationUrl_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=a&srv=https%3A%2F%2Fserver.example.com" +
                "&reg=http%3A%2F%2Fserver.example.com%2Fregister&pt=c",
        )

        assertTrue(result is PairingParseResult.Error)
        assertEquals("Registration URL must use https", (result as PairingParseResult.Error).reason)
    }

    @Test
    fun parse_schemelessServerUrl_returnsError() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=a&srv=server.example.com&pt=c",
        )

        assertTrue(result is PairingParseResult.Error)
    }
}
