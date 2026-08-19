package org.kysecurity.mail.contacts

import android.util.Patterns
import org.kysecurity.mail.data.ContactEntity

enum class RecipientField { TO, CC, BCC }

data class RecipientCandidate(
    val uid: String,
    val name: String,
    val email: String,
    val department: String? = null,
)

/** The primary (first) email; null when there is none, or it carries a recipient separator. */
fun ContactEntity.toRecipientCandidateOrNull(): RecipientCandidate? {
    val dto = toDto()
    val email = dto.emails.firstOrNull()?.value?.takeIf { it.isNotBlank() } ?: return null
    if (email.any { it in RECIPIENT_SEPARATORS }) return null
    return RecipientCandidate(uid = dto.uid, name = dto.fn, email = email, department = dto.department)
}

/** Characters that split one recipient string into several: "," is what this app joins chips with,
 *  and the relay rewrites ";" to "," before it parses the address list. */
private val RECIPIENT_SEPARATORS = charArrayOf(',', ';')

fun isDuplicateRecipient(existingEmails: List<String>, candidateEmail: String): Boolean =
    existingEmails.any { it.equals(candidateEmail, ignoreCase = true) }

/** [Patterns.EMAIL_ADDRESS] is the platform's standard "close enough to RFC 5322" validator —
 *  prefer it over hand-rolling a regex (AGENTS.md: prefer stdlib/platform APIs). */
fun isValidEmailFormat(email: String): Boolean = Patterns.EMAIL_ADDRESS.matcher(email).matches()

/** Case-insensitive range of the first match only, for bolding in the autocomplete dropdown. */
fun matchRanges(text: String, query: String): List<IntRange> {
    if (query.isBlank()) return emptyList()
    val index = text.indexOf(query, ignoreCase = true)
    if (index < 0) return emptyList()
    return listOf(index until (index + query.length))
}
