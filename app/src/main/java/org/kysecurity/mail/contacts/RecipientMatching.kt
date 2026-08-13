package org.kysecurity.mail.contacts

import android.util.Patterns
import org.kysecurity.mail.data.ContactEntity

/** Which composition field a picked contact should be appended to — shared between
 *  [org.kysecurity.mail.RecipientInputView] (single field) and [AddressBookSheet] (offers all three
 *  per row). */
enum class RecipientField { TO, CC, BCC }

data class RecipientCandidate(
    val uid: String,
    val name: String,
    val email: String,
    val department: String? = null,
)

/** Picks the contact's primary (first) email — same convention [ContactEditActivity] uses for its
 *  single-email field (see `loadExisting`). Returns null for contacts with no email at all —
 *  nothing usable to autocomplete to — and for one whose address carries a recipient separator.
 *
 *  The separator check is here rather than only at the input field because this is the single point
 *  both bypassing entry points share: picking from autocomplete and picking from [AddressBookSheet]
 *  each build a candidate and hand it straight to `RecipientInputView.addRecipient`, which never ran
 *  the format check that typed input gets. Chips are joined with "," on the wire, and the relay
 *  rewrites ";" to "," before parsing the address list, so a separator inside one contact's address
 *  silently turns a single picked chip into two SMTP recipients — and the chip renders the contact's
 *  display name, so the address is never shown again. `ContactsContract` has no per-account write
 *  ACL (see [toEntity]'s note on the same primitive), so any app holding `WRITE_CONTACTS` can set
 *  the value. */
fun ContactEntity.toRecipientCandidateOrNull(): RecipientCandidate? {
    val dto = toDto()
    val email = dto.emails.firstOrNull()?.value?.takeIf { it.isNotBlank() } ?: return null
    if (email.any { it in RECIPIENT_SEPARATORS }) return null
    return RecipientCandidate(uid = dto.uid, name = dto.fn, email = email, department = dto.department)
}

/** Characters that split one recipient string into several: "," is what this app joins chips with,
 *  and the relay rewrites ";" to "," before it parses the address list. */
private val RECIPIENT_SEPARATORS = charArrayOf(',', ';')

/** Case-insensitive duplicate check against a field's already-added recipient emails. */
fun isDuplicateRecipient(existingEmails: List<String>, candidateEmail: String): Boolean =
    existingEmails.any { it.equals(candidateEmail, ignoreCase = true) }

/** [Patterns.EMAIL_ADDRESS] is the platform's standard "close enough to RFC 5322" validator —
 *  prefer it over hand-rolling a regex (AGENTS.md: prefer stdlib/platform APIs). */
fun isValidEmailFormat(email: String): Boolean = Patterns.EMAIL_ADDRESS.matcher(email).matches()

/** Character range in [text] matching [query], case-insensitively — used to bold the matching
 *  substring in the autocomplete dropdown. Only the first occurrence is highlighted (dropdown rows
 *  are single-line; repeats aren't worth the extra spans). Empty when [query] is blank or absent. */
fun matchRanges(text: String, query: String): List<IntRange> {
    if (query.isBlank()) return emptyList()
    val index = text.indexOf(query, ignoreCase = true)
    if (index < 0) return emptyList()
    return listOf(index until (index + query.length))
}
