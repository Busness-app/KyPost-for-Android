package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

private fun email(id: String, sender: String, subject: String) =
    Email(id = id, subject = subject, sender = sender, preview = "", sourceMode = "relay")

class NotifiedMessageTest {

    @Test
    fun exactIdWinsOverEveryHint() {
        val target = email("uid-7", "someone@example.com", "Other subject")
        val decoy = email("uid-8", "ann@example.com", "Invoice")

        assertEquals(target, notifiedMessage(listOf(decoy, target), "uid-7", "ann@example.com", "Invoice"))
    }

    /** A pull payload with no `messageId` gets a synthesised `pull-<seq>` no row can carry. */
    @Test
    fun aUniqueSenderAndSubjectMatchResolvesASynthesisedId() {
        val target = email("uid-7", "Ann <ann@example.com>", "Invoice")
        val other = email("uid-8", "bob@example.com", "Lunch")

        assertEquals(target, notifiedMessage(listOf(other, target), "pull-42", "ann@example.com", "Invoice"))
    }

    /** The confidentiality rule: two candidates means the notification did not identify one. */
    @Test
    fun twoCandidatesAreRefusedRatherThanResolvedToTheFirst() {
        val first = email("uid-7", "Ann <ann@example.com>", "Invoice")
        val second = email("uid-9", "ann@example.com", "Invoice")

        assertNull(notifiedMessage(listOf(first, second), "pull-42", "ann@example.com", "Invoice"))
    }

    /** Substring collision: `ann@example.com` is inside `joann@example.com`. */
    @Test
    fun aSubstringCollisionOnTheSameSubjectIsRefused() {
        val target = email("uid-7", "ann@example.com", "Invoice")
        val collision = email("uid-9", "joann@example.com", "Invoice")

        assertNull(notifiedMessage(listOf(target, collision), "pull-42", "ann@example.com", "Invoice"))
    }

    @Test
    fun aBlankSenderNeverMatches() {
        val any = email("uid-7", "ann@example.com", "Invoice")

        assertNull(notifiedMessage(listOf(any), "pull-42", "", "Invoice"))
        assertNull(notifiedMessage(listOf(any), "pull-42", null, "Invoice"))
    }

    /** A push payload may carry no subject; matching on the sender alone is a guess. */
    @Test
    fun aBlankSubjectNeverMatches() {
        val any = email("uid-7", "ann@example.com", "")

        assertNull(notifiedMessage(listOf(any), "pull-42", "ann@example.com", ""))
        assertNull(notifiedMessage(listOf(any), "pull-42", "ann@example.com", null))
    }

    @Test
    fun aDifferentSubjectFromTheSameSenderIsNotTheNotifiedMessage() {
        val other = email("uid-7", "ann@example.com", "Lunch")

        assertNull(notifiedMessage(listOf(other), "pull-42", "ann@example.com", "Invoice"))
    }
}
