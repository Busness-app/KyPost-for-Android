package org.kysecurity.mail.contacts

import org.kysecurity.mail.data.ContactEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecipientMatchingTest {

    @Test
    fun toRecipientCandidateOrNull_usesPrimaryEmailAndDepartment() {
        val entity = ContactEntity(
            uid = "1",
            rev = 1,
            fn = "Ada Lovelace",
            department = "Analytical Engines",
            emailsJson = """[{"value":"ada@example.com"},{"value":"ada2@example.com"}]""",
        )

        val candidate = entity.toRecipientCandidateOrNull()

        assertEquals(RecipientCandidate("1", "Ada Lovelace", "ada@example.com", "Analytical Engines"), candidate)
    }

    @Test
    fun toRecipientCandidateOrNull_returnsNullWhenPrimaryEmailCarriesARecipientSeparator() {
        // ContactsContract has no per-account write ACL, so any app holding WRITE_CONTACTS can set
        // this value. Chips are joined with "," on the wire and the relay additionally rewrites ";"
        // to "," before parsing the address list, so a separator inside one contact's address turns
        // a single picked chip into two SMTP recipients — while the chip still shows only the
        // contact's display name.
        val comma = ContactEntity(
            uid = "1",
            rev = 1,
            fn = "Ada Lovelace",
            emailsJson = """[{"value":"ada@example.com,exfil@attacker.example"}]""",
        )
        val semicolon = ContactEntity(
            uid = "2",
            rev = 1,
            fn = "Ada Lovelace",
            emailsJson = """[{"value":"ada@example.com;exfil@attacker.example"}]""",
        )

        assertNull(comma.toRecipientCandidateOrNull())
        assertNull(semicolon.toRecipientCandidateOrNull())
    }

    @Test
    fun toRecipientCandidateOrNull_returnsNullWhenNoEmail() {
        val entity = ContactEntity(uid = "1", rev = 1, fn = "No Email Guy", emailsJson = "[]")

        assertNull(entity.toRecipientCandidateOrNull())
    }

    @Test
    fun isDuplicateRecipient_matchesCaseInsensitively() {
        assertTrue(isDuplicateRecipient(listOf("Ada@Example.com"), "ada@example.com"))
        assertFalse(isDuplicateRecipient(listOf("bob@example.com"), "ada@example.com"))
        assertFalse(isDuplicateRecipient(emptyList(), "ada@example.com"))
    }

    @Test
    fun matchRanges_findsFirstCaseInsensitiveOccurrence() {
        assertEquals(listOf(0..1), matchRanges("Ada Lovelace", "ad"))
        assertEquals(listOf(4..11), matchRanges("Ada Lovelace", "Lovelace"))
        assertEquals(emptyList<IntRange>(), matchRanges("Ada Lovelace", "zz"))
        assertEquals(emptyList<IntRange>(), matchRanges("Ada Lovelace", ""))
    }
}
