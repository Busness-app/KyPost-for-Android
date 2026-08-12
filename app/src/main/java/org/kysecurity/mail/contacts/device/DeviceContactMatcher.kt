package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactDto

object DeviceContactMatcher {
    fun normalizeEmail(email: String): String {
        return email.trim().lowercase()
    }

    /** Strips non-digits, then drops a leading NANP "1" country code (11 digits, e.g.
     *  "+1 555 123 4567") so it normalizes the same as its 10-digit form ("555-123-4567") —
     *  device contacts and server-synced contacts don't consistently store one or the other. */
    fun normalizePhone(phone: String): String {
        val digits = phone.replace(Regex("[^0-9]"), "")
        return if (digits.length == 11 && digits.startsWith("1")) digits.substring(1) else digits
    }

    /**
     * Every normalized email and phone in [existing], mapped to the uid that owns it.
     *
     * Built once per sync and reused across candidates. [findMatch] used to rescan and re-normalize
     * the whole contact list for every candidate, so a device with 2,000 contacts and a Room store
     * of 2,000 did millions of string comparisons per sync cycle — and re-derived the same
     * normalized values every time.
     *
     * Each value carries its owner's position in [existing], and [Index.findMatch] returns the
     * lowest-positioned match. That reproduces the old scan exactly — "the first contact in list
     * order that matches on either an email or a phone" — rather than quietly preferring whichever
     * field happens to be checked first.
     */
    class Index private constructor(private val byValue: Map<String, Match>) {
        private data class Match(val uid: String, val ordinal: Int)

        fun findMatch(candidateEmails: List<String>, candidatePhones: List<String>): String? {
            val keys = candidateEmails.mapNotNull { emailKey(it) } + candidatePhones.mapNotNull { phoneKey(it) }
            return keys.mapNotNull { byValue[it] }.minByOrNull { it.ordinal }?.uid
        }

        companion object {
            fun of(existing: List<ContactDto>): Index {
                val byValue = HashMap<String, Match>()
                existing.forEachIndexed { ordinal, contact ->
                    val match = Match(contact.uid, ordinal)
                    (
                        contact.emails.mapNotNull { emailKey(it.value) } +
                            contact.phones.mapNotNull { phoneKey(it.value) }
                        )
                        .forEach { key ->
                            val current = byValue[key]
                            if (current == null || ordinal < current.ordinal) byValue[key] = match
                        }
                }
                return Index(byValue)
            }
        }
    }

    /**
     * Emails and phones share one map, so they are namespaced to keep a phone-shaped email from
     * matching a phone.
     *
     * Null for a value that normalizes to nothing, which identifies nobody. `normalizePhone` strips
     * every non-digit, so placeholders like "n/a", "-" and "+" all collapse to the empty string, and
     * `ContactFieldDto.value` defaults to empty server-side. Indexing those made one stored
     * placeholder a bucket that every later blank-valued candidate matched, so unrelated device
     * contacts were reported as already-known and silently skipped from import.
     */
    private fun emailKey(value: String): String? =
        normalizeEmail(value).takeIf { it.isNotBlank() }?.let { "e:$it" }

    private fun phoneKey(value: String): String? =
        normalizePhone(value).takeIf { it.isNotBlank() }?.let { "p:$it" }

    fun findMatch(
        candidateEmails: List<String>,
        candidatePhones: List<String>,
        existing: List<ContactDto>,
    ): String? = Index.of(existing).findMatch(candidateEmails, candidatePhones)
}
