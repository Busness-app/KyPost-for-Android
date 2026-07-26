package com.urlxl.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaNumberMatchTest {

    @Test
    fun offersThreeChoicesIncludingTheCorrectOne() {
        val options = MfaNumberMatch.optionsFor("challenge-1", correct = "42", serverDecoys = emptyList())

        assertEquals(MfaNumberMatch.CHOICE_COUNT, options!!.size)
        assertTrue("correct value missing from $options", "42" in options)
        assertEquals("choices must be distinct", options.size, options.distinct().size)
    }

    /**
     * The buttons must not move under the user's finger. `onNewIntent`, a recreate, or a return
     * from the biometric prompt all rebuild this list.
     */
    @Test
    fun isStableForTheSameChallenge() {
        val first = MfaNumberMatch.optionsFor("challenge-1", "42", emptyList())
        val second = MfaNumberMatch.optionsFor("challenge-1", "42", emptyList())

        assertEquals(first, second)
    }

    @Test
    fun differentChallengesDoNotAllPutTheAnswerInTheSamePlace() {
        val positions = (1..40).map { n ->
            MfaNumberMatch.optionsFor("challenge-$n", "42", emptyList())!!.indexOf("42")
        }.toSet()

        assertTrue("the answer was always at the same index — that is a free guess", positions.size > 1)
    }

    @Test
    fun prefersServerSuppliedDecoys() {
        val options = MfaNumberMatch.optionsFor("challenge-1", "42", listOf("17", "83"))

        assertEquals(setOf("42", "17", "83"), options!!.toSet())
    }

    @Test
    fun ignoresAServerDecoyThatDuplicatesTheAnswer() {
        val options = MfaNumberMatch.optionsFor("challenge-1", "42", listOf("42", "17"))

        assertEquals(MfaNumberMatch.CHOICE_COUNT, options!!.size)
        assertEquals("42 must appear exactly once", 1, options.count { it == "42" })
    }

    /** No digits means the server does not support number matching; the caller falls back to the
     *  plain approve/deny buttons rather than inventing an answer. */
    @Test
    fun returnsNullWhenTheServerSentNoMatchDigits() {
        assertNull(MfaNumberMatch.optionsFor("challenge-1", "", emptyList()))
        assertNull(MfaNumberMatch.optionsFor("challenge-1", "7", emptyList()))
    }
}
