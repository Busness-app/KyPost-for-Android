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
