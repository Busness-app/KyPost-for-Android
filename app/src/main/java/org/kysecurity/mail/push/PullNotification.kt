package org.kysecurity.mail.push

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Delivery mode mirrored from the server; the server value is authoritative. */
enum class DeliveryMode(val wire: String) {
    PUSH("push"),
    PULL("pull");

    companion object {
        /** Anything other than an explicit "pull" is treated as push (the safe default). */
        fun fromWire(value: String?): DeliveryMode =
            if (value?.trim()?.lowercase() == PULL.wire) PULL else PUSH
    }
}

/** The transport the server confirmed on the last successful registration. */
enum class PushTransport(val wire: String) {
    FCM("fcm"),
    APNS("apns"),
    UNIFIED_PUSH("unifiedpush");

    companion object {
        /** Null for absent or unrecognised values — older servers do not echo the field back. */
        fun fromWire(value: String?): PushTransport? {
            val normalized = value?.trim()?.lowercase() ?: return null
            return entries.firstOrNull { it.wire == normalized }
        }
    }
}

/** One notification returned by the pull endpoint. */
@Serializable
data class PullNotification(
    @SerialName("seq") val seq: Long,
    @SerialName("title") val title: String = "",
    @SerialName("body") val body: String = "",
    @SerialName("data") val data: Map<String, String>? = null,
    @SerialName("createdAt") val createdAt: String? = null,
) {
    /** Redacted: the body is message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "PullNotification(redacted)"
}

/** Body of a 200 response from the pull endpoint. */
@Serializable
data class PullNotificationsResponse(
    @SerialName("deliveryMode") val deliveryMode: String? = null,
    @SerialName("cursor") val cursor: Long = 0L,
    @SerialName("notifications") val notifications: List<PullNotification> = emptyList(),
) {
    val mode: DeliveryMode get() = DeliveryMode.fromWire(deliveryMode)
}

/** Maps a pulled notification onto [PushPayload]; synthesizes an id from `seq` when absent. */
fun PullNotification.toPushPayload(nowEpochMs: Long = System.currentTimeMillis()): PushPayload {
    val fields = data ?: emptyMap()
    val messageId = fields["messageId"]?.takeIf { it.isNotBlank() } ?: "pull-$seq"
    val senderName = title.ifBlank { fields["sender"].orEmpty() }.trim()
    val subject = body.ifBlank { fields["subject"].orEmpty() }.trim()
    return PushPayload(
        messageId = messageId,
        senderName = senderName,
        emailSubject = subject,
        keywords = emptyList(),
        receivedAtEpochMs = parseRfc3339Millis(createdAt) ?: nowEpochMs,
    )
}

private fun parseRfc3339Millis(value: String?): Long? {
    val raw = value?.trim().orEmpty()
    if (raw.isBlank()) return null
    return runCatching { java.time.Instant.parse(raw).toEpochMilli() }.getOrNull()
}

/** Side-effect free so cursor/de-duplication behavior is unit testable. */
object PullNotificationProcessor {
    data class Prepared(
        val payloads: List<PushPayload>,
        val nextCursor: Long,
    )

    fun prepare(
        response: PullNotificationsResponse,
        currentCursor: Long,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): Prepared {
        val payloads = response.notifications
            .filter { it.seq > currentCursor }
            .distinctBy { it.seq }
            .sortedBy { it.seq }
            .map { it.toPushPayload(nowEpochMs) }
        // response.cursor is the highest sequence the server has assigned; never move backwards.
        val nextCursor = maxOf(currentCursor, response.cursor)
        return Prepared(payloads = payloads, nextCursor = nextCursor)
    }
}