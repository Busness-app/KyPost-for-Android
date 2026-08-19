package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.PendingContactChangeEntity
import kotlinx.serialization.json.Json

// The wire carries no correlation id, so creates are matched by content, in push order.
object ContactSyncReconciliation {
    private val json = Json { ignoreUnknownKeys = true }

    /** Returns a map of localUid -> server-assigned uid for every create that could be matched. */
    fun reconcile(pendingCreates: List<PendingContactChangeEntity>, changed: List<ContactDto>): Map<String, String> {
        if (pendingCreates.isEmpty() || changed.isEmpty()) return emptyMap()

        val claimedIndices = mutableSetOf<Int>()
        val result = mutableMapOf<String, String>()

        for (pending in pendingCreates) {
            val payload = runCatching { json.decodeFromString<ContactDto>(pending.payloadJson) }.getOrNull() ?: continue
            val match = changed.withIndex().firstOrNull { (index, candidate) ->
                index !in claimedIndices && candidate.uid.isNotBlank() && contentMatches(payload, candidate)
            }
            if (match != null) {
                claimedIndices += match.index
                result[pending.localUid] = match.value.uid
            }
        }
        return result
    }

    private fun contentMatches(payload: ContactDto, candidate: ContactDto): Boolean {
        return payload.fn == candidate.fn &&
            payload.org == candidate.org &&
            payload.emails.map { it.value } == candidate.emails.map { it.value } &&
            payload.phones.map { it.value } == candidate.phones.map { it.value }
    }
}
