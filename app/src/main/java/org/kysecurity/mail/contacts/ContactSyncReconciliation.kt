package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.PendingContactChangeEntity
import kotlinx.serialization.json.Json

/**
 * Matches locally-created (not-yet-synced) contacts to their server-assigned uid in a push
 * response. The wire protocol has no client-supplied correlation id (Mobile_Contact_Sync.md
 * Part 2 explicitly calls this out), so this matches by content — a pending create's serialized
 * fn/org/emails/phones against each unclaimed entry in [changed] — in push order, claiming the
 * first unclaimed exact match per pending create.
 */
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
