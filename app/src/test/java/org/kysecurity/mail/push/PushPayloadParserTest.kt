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
}

