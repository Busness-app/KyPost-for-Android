package org.kysecurity.mail.push

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Delivery mode for a subscriber, mirrored from the server. "push" is the existing
 * FCM-relay path; "pull" means FCM sends nothing and the app must poll the server
 * directly via the pull endpoint. The server value is authoritative — see the
 * `deliveryMode` field on both the register response and the pull response.
 */
enum class DeliveryMode(val wire: String) {
    PUSH("push"),
    PULL("pull");

    companion object {
        /** Anything other than an explicit "pull" is treated as push (the safe default). */
        fun fromWire(value: String?): DeliveryMode =
            if (value?.trim()?.lowercase() == PULL.wire) PULL else PUSH
    }
}

/**
 * How the server reaches this device — the transport it confirmed on the last successful
 * registration.
 */
enum class PushTransport(val wire: String) {
    FCM("fcm"),
    APNS("apns"),
    UNIFIED_PUSH("unifiedpush");

    companion object {
        /** Null for absent or unrecognised values — older servers do not echo the field back at
         *  all, and "the server said something we do not understand" must not read as any
         *  particular transport. */
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

/**
 * Maps a pulled notification onto the same [PushPayload] the FCM data-message path
 * produces, so pull and push notifications render identically and share the tap
 * handler. When the pull `data` object omits `messageId`, we synthesize a stable id
 * from the strictly-increasing `seq` so de-duplication (by notification id) still holds.
 */
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

/**
 * Pure logic for turning a pull response into the notifications to show and the next
 * cursor. Kept side-effect free so cursor/de-duplication behavior is unit testable.
 */
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