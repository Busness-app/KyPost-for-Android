package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The per-field recipient split behind the delivery grouping.
 *
 * Deliberately **not** [com.urlxl.mail.splitAddresses], which flattens To/CC/BCC into one list and
 * dedupes across them. That is right for the preflight, where the question is "which addresses need
 * a key" and asking twice about one person is just noise. Here it would collapse a BCC into the To
 * bucket — putting a blind recipient in a header every other recipient can read.
 */
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

    /**
     * An address in both To and BCC is not a blind recipient — it is already visible in the To
     * header. Keeping it in the BCC bucket would build it a second, redundant delivery *and* leave
     * the sender believing that copy was blind.
     */
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
