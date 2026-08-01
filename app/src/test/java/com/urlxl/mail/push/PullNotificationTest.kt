package com.urlxl.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PullNotificationTest {

    @Test
    fun deliveryMode_fromWire_defaultsToPush() {
        assertEquals(DeliveryMode.PULL, DeliveryMode.fromWire("pull"))
        assertEquals(DeliveryMode.PULL, DeliveryMode.fromWire(" PULL "))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire("push"))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire(null))
        assertEquals(DeliveryMode.PUSH, DeliveryMode.fromWire("something-else"))
    }

    @Test
    fun resolvePullEndpoint_prefersProvided_elseDerives() {
        assertEquals(
            "https://server.example.com/custom/pull",
            resolvePullEndpoint("https://server.example.com", "https://server.example.com/custom/pull"),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com/", null),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "  "),
        )
    }

    @Test
    fun resolvePullEndpoint_rejectsDifferentPortAndUnsafeUrl() {
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "https://server.example.com:8443/pull"),
        )
        assertEquals(
            "https://server.example.com/api/notifications/native/pull",
            resolvePullEndpoint("https://server.example.com", "http://server.example.com/pull"),
        )
    }

    @Test
    fun toPushPayload_usesTitleAndBody_andFallsBackToData() {
        val n = PullNotification(
            seq = 42,
            title = "Alice",
            body = "Subject line",
            data = mapOf("messageId" to "abc", "url" to "/read"),
            createdAt = "2026-07-05T12:34:56Z",
        )
        val payload = n.toPushPayload(nowEpochMs = 1L)
        assertEquals("abc", payload.messageId)
        assertEquals("Alice", payload.senderName)
        assertEquals("Subject line", payload.emailSubject)
    }

    @Test
    fun toPushPayload_synthesizesMessageIdFromSeq_whenAbsent() {
        val n = PullNotification(seq = 7, title = "T", body = "B", data = null, createdAt = null)
        val payload = n.toPushPayload(nowEpochMs = 99L)
        assertEquals("pull-7", payload.messageId)
        assertEquals(99L, payload.receivedAtEpochMs)
    }

    @Test
    fun toPushPayload_fallsBackToDataSenderSubject_whenTitleBodyBlank() {
        val n = PullNotification(
            seq = 3,
            title = "",
            body = "",
            data = mapOf("sender" to "Bob", "subject" to "Hi"),
        )
        val payload = n.toPushPayload(nowEpochMs = 1L)
        assertEquals("Bob", payload.senderName)
        assertEquals("Hi", payload.emailSubject)
    }

    @Test
    fun processor_filtersSeqAtOrBelowCursor_andSortsBySeq() {
        val response = PullNotificationsResponse(
            deliveryMode = "pull",
            cursor = 12,
            notifications = listOf(
                PullNotification(seq = 12, title = "c"),
                PullNotification(seq = 10, title = "a"),
                PullNotification(seq = 11, title = "b"),
                PullNotification(seq = 9, title = "old"), // <= cursor, dropped
            ),
        )
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 9, nowEpochMs = 1L)
        assertEquals(listOf("pull-10", "pull-11", "pull-12"), prepared.payloads.map { it.messageId })
        assertEquals(12L, prepared.nextCursor)
    }

    @Test
    fun processor_deduplicatesBySeq() {
        val response = PullNotificationsResponse(
            cursor = 5,
            notifications = listOf(
                PullNotification(seq = 5, title = "one"),
                PullNotification(seq = 5, title = "dup"),
            ),
        )
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 0, nowEpochMs = 1L)
        assertEquals(1, prepared.payloads.size)
    }

    @Test
    fun processor_neverMovesCursorBackwards() {
        // Server reports a lower cursor than we already have (e.g. stale/no new items).
        val response = PullNotificationsResponse(cursor = 3, notifications = emptyList())
        val prepared = PullNotificationProcessor.prepare(response, currentCursor = 20, nowEpochMs = 1L)
        assertTrue(prepared.payloads.isEmpty())
        assertEquals(20L, prepared.nextCursor)
    }

    @Test
    fun retryAfter_parsesDeltaSeconds_ignoresGarbage() {
        assertEquals(30L, PullNotificationClient.parseRetryAfterSeconds("30"))
        assertNull(PullNotificationClient.parseRetryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT"))
        assertNull(PullNotificationClient.parseRetryAfterSeconds(null))
        assertNull(PullNotificationClient.parseRetryAfterSeconds("-5"))
    }
}
