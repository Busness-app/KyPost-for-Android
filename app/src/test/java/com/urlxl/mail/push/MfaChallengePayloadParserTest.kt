package com.urlxl.mail.push

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
                "approxLocation" to "Berlin, DE",
                "userAgent" to "Firefox on Linux",
                "issuedAt" to "1750000000000",
                "matchDigits" to "42",
                "decoyDigits" to "17, 83",
            ),
        )

        requireNotNull(payload)
        assertEquals("203.0.113.7", payload.ipAddress)
        assertEquals("Berlin, DE", payload.approxLocation)
        assertEquals("Firefox on Linux", payload.userAgent)
        assertEquals(1750000000000L, payload.issuedAtEpochMs)
        assertEquals("42", payload.matchDigits)
        assertEquals(listOf("17", "83"), payload.decoyDigits)
    }

    /** A server that has not been updated must keep working — the screen degrades to naming what
     *  it does not know, rather than the challenge being rejected. */
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

    /** matchDigits drives a tap target, so nobody who can reach the push channel gets to put
     *  arbitrary text on a button. */
    @Test
    fun parse_dropsMalformedMatchDigits() {
        fun digitsFor(value: String) = MfaChallengePayloadParser.parse(
            mapOf("type" to "mfa_challenge", "challengeId" to "c-1", "matchDigits" to value),
        )!!.matchDigits

        assertEquals("", digitsFor("APPROVE"))
        assertEquals("", digitsFor("4"))
        assertEquals("", digitsFor("4242"))
        assertEquals("", digitsFor("4a"))
        assertEquals("42", digitsFor("42"))
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
}
