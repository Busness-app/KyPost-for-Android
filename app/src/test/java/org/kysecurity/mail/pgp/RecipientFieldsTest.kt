package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** Deliberately not [org.kysecurity.mail.splitAddresses], which would collapse a BCC into To. */
class RecipientFieldsTest {

    @Test
    fun splitsEachFieldIndependently() {
        val fields = splitRecipientFields(
            to = "alice@example.invalid, bob@example.invalid",
            cc = "carol@example.invalid",
            bcc = "dave@example.invalid",
        )

        assertEquals(listOf("alice@example.invalid", "bob@example.invalid"), fields.to)
        assertEquals(listOf("carol@example.invalid"), fields.cc)
        assertEquals(listOf("dave@example.invalid"), fields.bcc)
    }

    @Test
    fun dedupesWithinAFieldCaseInsensitivelyKeepingTheFirstSpelling() {
        val fields = splitRecipientFields(
            to = "Alice@Example.invalid, alice@example.invalid",
            cc = "",
            bcc = "",
        )

        assertEquals(listOf("Alice@Example.invalid"), fields.to)
    }

    /** An address in both To and BCC is already visible in the To header, so it is not blind. */
    @Test
    fun anAddressAlreadyInToIsDroppedFromCcAndBcc() {
        val fields = splitRecipientFields(
            to = "alice@example.invalid",
            cc = "ALICE@example.invalid, carol@example.invalid",
            bcc = "alice@example.INVALID, dave@example.invalid",
        )

        assertEquals(listOf("alice@example.invalid"), fields.to)
        assertEquals(listOf("carol@example.invalid"), fields.cc)
        assertEquals(listOf("dave@example.invalid"), fields.bcc)
    }

    @Test
    fun anAddressAlreadyInCcIsDroppedFromBcc() {
        val fields = splitRecipientFields(
            to = "alice@example.invalid",
            cc = "carol@example.invalid",
            bcc = "Carol@example.invalid, dave@example.invalid",
        )

        assertEquals(listOf("carol@example.invalid"), fields.cc)
        assertEquals(listOf("dave@example.invalid"), fields.bcc)
    }

    @Test
    fun blankAndWhitespaceOnlyEntriesAreDropped() {
        val fields = splitRecipientFields(to = " alice@example.invalid , , ", cc = "  ", bcc = "")

        assertEquals(listOf("alice@example.invalid"), fields.to)
        assertEquals(emptyList<String>(), fields.cc)
        assertEquals(emptyList<String>(), fields.bcc)
    }
}
