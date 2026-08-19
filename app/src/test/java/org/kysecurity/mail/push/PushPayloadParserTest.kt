package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PushPayloadParserTest {

    @Test
    fun parse_readsContractKeysExactly() {
        val payload = PushPayloadParser.parse(
            mapOf(
                "messageId" to "m-1",
                "senderName" to "A. Sender",
                "emailSubject" to "Subject line",
                "Keywords" to "Finance, Urgent, Team",
            ),
            nowEpochMs = 77L,
        )

        requireNotNull(payload)
        assertEquals("m-1", payload.messageId)
        assertEquals("A. Sender", payload.senderName)
        assertEquals("Subject line", payload.emailSubject)
        assertEquals(listOf("Finance", "Urgent", "Team"), payload.keywords)
        assertEquals(77L, payload.receivedAtEpochMs)
    }

    @Test
    fun parse_missingMessageId_returnsNull() {
        val payload = PushPayloadParser.parse(
            mapOf("senderName" to "A", "emailSubject" to "B", "Keywords" to "K"),
        )

        assertNull(payload)
    }

    @Test
    fun parse_emptyKeywords_returnsEmptyList() {
        val payload = PushPayloadParser.parse(
            mapOf(
                "messageId" to "m-1",
                "senderName" to "",
                "emailSubject" to "",
                "Keywords" to "",
            ),
        )

        requireNotNull(payload)
        assertTrue(payload.keywords.isEmpty())
        assertEquals("New email", PushPayloadParser.title(payload))
        assertEquals("You received a new labeled email", PushPayloadParser.body(payload))
    }

    /** These land in a notification AND in the persisted `push_state` history, so an unbounded
     *  relay string is a file the app later OOMs reading. Same rule MfaChallengePayloadParser
     *  already applies to its own fields on the same delivery channel. */
    @Test
    fun parse_boundsEveryRelaySuppliedString() {
        val payload = PushPayloadParser.parse(
            mapOf(
                "messageId" to "m".repeat(10_000),
                "senderName" to "s".repeat(10_000),
                "emailSubject" to "j".repeat(10_000),
            ),
        )

        requireNotNull(payload)
        assertEquals(PushPayloadParser.MAX_MESSAGE_ID_LENGTH, payload.messageId.length)
        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, payload.senderName.length)
        assertEquals(PushPayloadParser.MAX_HEADER_LENGTH, payload.emailSubject.length)
    }

    @Test
    fun parse_boundsKeywordCountAndLength() {
        val payload = PushPayloadParser.parse(
            mapOf(
                "messageId" to "m-1",
                "Keywords" to (
                    (1..500).joinToString(",") { "k$it" } +
                        "," + "x".repeat(PushPayloadParser.MAX_KEYWORD_LENGTH + 1)
                    ),
            ),
        )

        requireNotNull(payload)
        assertEquals(PushPayloadParser.MAX_KEYWORDS, payload.keywords.size)
        assertTrue(payload.keywords.all { it.length <= PushPayloadParser.MAX_KEYWORD_LENGTH })
    }
}

