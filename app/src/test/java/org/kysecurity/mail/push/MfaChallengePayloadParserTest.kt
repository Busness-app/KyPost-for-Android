package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MfaChallengePayloadParserTest {

    @Test
    fun parse_readsTheSignInContextTheApprovalScreenShows() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf(
                "type" to "mfa_challenge",
                "challengeId" to "c-1",
                "ipAddress" to "203.0.113.7",
                "userAgent" to "Firefox on Linux",
                "issuedAt" to "1750000000000",
                "matchDigits" to "42",
                "decoyDigits" to "17, 83",
            ),
        )

        requireNotNull(payload)
        assertEquals("203.0.113.7", payload.ipAddress)
        assertEquals("Firefox on Linux", payload.userAgent)
        assertEquals(1750000000000L, payload.issuedAtEpochMs)
        assertEquals("42", payload.matchDigits)
        assertEquals(listOf("17", "83"), payload.decoyDigits)
    }

    @Test
    fun parse_toleratesAPayloadWithNoContextAtAll() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf("type" to "mfa_challenge", "challengeId" to "c-1"),
        )

        requireNotNull(payload)
        assertEquals("c-1", payload.challengeId)
        assertEquals("", payload.ipAddress)
        assertEquals("", payload.matchDigits)
        assertEquals(emptyList<String>(), payload.decoyDigits)
    }

    @Test
    fun parse_dropsMalformedMatchDigits() {
        fun digitsFor(value: String) = MfaChallengePayloadParser.parse(
            mapOf("type" to "mfa_challenge", "challengeId" to "c-1", "matchDigits" to value),
        )!!.matchDigits

        assertEquals("", digitsFor("APPROVE"))
        assertEquals("", digitsFor("4a"))
        assertEquals("", digitsFor("1234567"))
        assertEquals("42", digitsFor("42"))
    }

    @Test
    fun parse_acceptsWiderMatchDigitsThanTheServerCurrentlySends() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf(
                "type" to "mfa_challenge",
                "challengeId" to "c-1",
                "matchDigits" to "047",
                "decoyDigits" to "128,935",
            ),
        )!!

        assertEquals("047", payload.matchDigits)
        assertEquals(listOf("128", "935"), payload.decoyDigits)
    }

    @Test
    fun parse_boundsContextStringsSoTheyCannotPushTheButtonsOffScreen() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf(
                "type" to "mfa_challenge",
                "challengeId" to "c-1",
                "userAgent" to "x".repeat(5_000),
            ),
        )

        assertEquals(120, payload!!.userAgent.length)
    }

    @Test
    fun parse_readsContractKeysExactly() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf(
                "type" to "mfa_challenge",
                "challengeId" to "ch-123",
            ),
        )
        requireNotNull(payload)
        assertEquals("ch-123", payload.challengeId)
    }

    @Test
    fun parse_wrongType_returnsNull() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf(
                "type" to "something_else",
                "challengeId" to "ch-123",
            ),
        )
        assertNull(payload)
    }

    @Test
    fun parse_missingType_returnsNull() {
        val payload = MfaChallengePayloadParser.parse(mapOf("challengeId" to "ch-123"))
        assertNull(payload)
    }

    @Test
    fun parse_blankChallengeId_returnsNull() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf("type" to "mfa_challenge", "challengeId" to "   "),
        )
        assertNull(payload)
    }

    @Test
    fun parse_oversizedChallengeId_returnsNull() {
        val payload = MfaChallengePayloadParser.parse(
            mapOf("type" to "mfa_challenge", "challengeId" to "c".repeat(129)),
        )
        assertNull(payload)
    }

    @Test
    fun parse_challengeIdWithUnexpectedCharacters_returnsNull() {
        // Server-minted opaque ids are UUID-shaped. Anything else is not a challenge id we should
        // be writing to disk under the attacker's choice of name.
        listOf(
            "../../etc/passwd",
            "c 1",
            // A NUL is the classic way to make a name read as one thing and resolve as
            // another. Written as an escape, never as a literal byte in the source file.
            "c\u00001",
            "c/1",
            "<script>",
        ).forEach { hostileId ->
            assertNull(
                hostileId,
                MfaChallengePayloadParser.parse(
                    mapOf("type" to "mfa_challenge", "challengeId" to hostileId),
                ),
            )
        }
    }

    @Test
    fun parse_acceptsTheIdShapesRealServersMint() {
        listOf(
            "c-1",
            "9f8b1c2d-4e5a-6789-abcd-ef0123456789",
            "chal_01HZY.MFA:7",
        ).forEach { id ->
            val payload = MfaChallengePayloadParser.parse(
                mapOf("type" to "mfa_challenge", "challengeId" to id),
            )
            assertEquals(id, requireNotNull(payload).challengeId)
        }
    }
}
