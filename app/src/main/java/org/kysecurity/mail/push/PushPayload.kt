package org.kysecurity.mail.push

import kotlinx.serialization.Serializable

@Serializable
data class PushPayload(
    val messageId: String,
    val senderName: String,
    val emailSubject: String,
    val keywords: List<String>,
    val receivedAtEpochMs: Long,
)

object PushPayloadParser {
    fun parse(data: Map<String, String>, nowEpochMs: Long = System.currentTimeMillis()): PushPayload? {
        val messageId = data["messageId"].orEmpty().trim()
        if (messageId.isBlank()) return null

        val senderName = data["senderName"].orEmpty().trim()
        val emailSubject = data["emailSubject"].orEmpty().trim()
        // Accept either casing. The server sends "Keywords" while every other field is camelCase,
        // and a lone capital letter silently degrading to an empty keyword list is not a failure
        // mode worth keeping load-bearing.
        val keywordsCsv = (data["keywords"] ?: data["Keywords"]).orEmpty()

        return PushPayload(
            messageId = messageId,
            senderName = senderName,
            emailSubject = emailSubject,
            keywords = keywordsCsv
                .split(',')
                .map { it.trim() }
                .filter { it.isNotBlank() },
            receivedAtEpochMs = nowEpochMs,
        )
    }

    fun title(payload: PushPayload): String {
        return payload.senderName.ifBlank { "New email" }
    }

    fun body(payload: PushPayload): String {
        return payload.emailSubject.ifBlank { "You received a new labeled email" }
    }
}

