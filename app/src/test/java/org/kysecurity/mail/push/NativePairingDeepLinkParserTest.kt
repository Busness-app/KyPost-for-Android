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
        // A stale QR from before the per-device-secret migration may carry hash=; ignore it.
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&hash=stale-hash&srv=https%3A%2F%2Fserver.example.com&pt=token",
        )

        assertTrue(result is PairingParseResult.Success)
        val pairing = (result as PairingParseResult.Success).pairing
        assertEquals(null, pairing.deviceSecret)
    }

    @Test
    /** A blank `registrationUrl` is meaningless downstream — the store reads it as "no pairing"
     *  and registration rejects it — so an absent `reg` is resolved here rather than emitted blank
     *  for each consumer to remember to patch up. */
    fun parse_missingReg_resolvesTheDefaultRegistrationUrl() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=subscriber-123&srv=https%3A%2F%2Fserver.example.com&pt=token",
        )

        val pairing = (result as PairingParseResult.Success).pairing
        assertEquals(
            "https://server.example.com/api/notifications/native/register",
            pairing.registrationUrl,
        )
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

    /** `kypost://native-pair` is BROWSABLE: any page or app can hand this parser any string, so
     *  the only acceptable outcome for ALL of them is a [PairingParseResult], never a throw.
     *  Malformed percent escapes are the interesting family — `URLDecoder.decode("%")` throws
     *  `IllegalArgumentException`, and the only thing standing between that and the pairing screen
     *  is how strict `java.net.URI` happens to be about escapes. */
    @Test
    fun parse_hostileDeepLinks_alwaysReturnARefusalAndNeverThrow() {
        val hostile = listOf(
            "kypost://native-pair?sub=%&srv=x&pt=y",
            "kypost://native-pair?sub=%zz&srv=x&pt=y",
            "kypost://native-pair?sub=a%&srv=x&pt=y",
            "kypost://native-pair?sub=%E0%A4%A&srv=x&pt=y",
            "kypost://native-pair?%=%&%=%",
            // Syntactically valid escapes that decode to invalid UTF-8; these must NOT be refused
            // by throwing either, though they do get past the decoder.
            "kypost://native-pair?sub=%FF&srv=%FF&pt=%FF",
            "kypost://native-pair?",
            "kypost://native-pair?&&&",
            "kypost://native-pair?" + "sub=a&".repeat(5_000),
            "kypost://native-pair?sub=" + "a".repeat(100_000),
        )

        for (link in hostile) {
            val result = NativePairingDeepLinkParser.parse(link)
            assertTrue("$link produced $result", result is PairingParseResult.Error)
        }
    }

    /** A duplicated field must not be ambiguous: last write wins, deterministically. */
    @Test
    fun parse_duplicateFields_takesTheLastOccurrence() {
        val result = NativePairingDeepLinkParser.parse(
            "kypost://native-pair?sub=first&sub=second&srv=https%3A%2F%2Fserver.example.com&pt=c",
        )

        assertTrue(result is PairingParseResult.Success)
        assertEquals("second", (result as PairingParseResult.Success).pairing.subscriberId)
    }
}
