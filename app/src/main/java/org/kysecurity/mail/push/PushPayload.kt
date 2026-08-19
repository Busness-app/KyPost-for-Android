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

    /** Bounded for the same reasons [MfaChallengePayloadParser] bounds its own fields, on the same
     *  delivery channel: these strings are rendered into a notification AND serialised into the
     *  `push_state` DataStore, [HISTORY_LIMIT] of them at a time. Unbounded, a hostile relay turns
     *  that file into something the app OOMs on before any code that could delete it runs. */
    internal const val MAX_MESSAGE_ID_LENGTH = 256
    internal const val MAX_HEADER_LENGTH = 512

    /** A notification shows one line of each; the rest is retained cost, never displayed. */
    internal const val MAX_KEYWORDS = 32
    internal const val MAX_KEYWORD_LENGTH = org.kysecurity.mail.KeywordSettings.MAX_KEYWORD_LENGTH

    fun parse(data: Map<String, String>, nowEpochMs: Long = System.currentTimeMillis()): PushPayload? {
        val messageId = data["messageId"].orEmpty().trim().take(MAX_MESSAGE_ID_LENGTH)
        if (messageId.isBlank()) return null

        val senderName = data["senderName"].orEmpty().trim().take(MAX_HEADER_LENGTH)
        val emailSubject = data["emailSubject"].orEmpty().trim().take(MAX_HEADER_LENGTH)
        // Accept either casing: the server sends "Keywords" while every other field is camelCase.
        val keywordsCsv = (data["keywords"] ?: data["Keywords"]).orEmpty()

        return PushPayload(
            messageId = messageId,
            senderName = senderName,
            emailSubject = emailSubject,
            keywords = keywordsCsv
                .splitToSequence(',')
                .map { it.trim() }
                .filter { it.isNotBlank() && it.length <= MAX_KEYWORD_LENGTH }
                .take(MAX_KEYWORDS)
                .toList(),
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

