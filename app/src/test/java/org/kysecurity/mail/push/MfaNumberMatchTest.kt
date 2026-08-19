package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MfaNumberMatchTest {

    /** Pinned order, so assertions can be about content rather than luck. */
    private val noShuffle: (List<String>) -> List<String> = { it }

    @Test
    fun offersTheServersThreeValues() {
        val options = MfaNumberMatch.optionsFor("42", listOf("17", "83"), noShuffle)

        assertEquals(MfaNumberMatch.CHOICE_COUNT, options!!.size)
        assertEquals(setOf("42", "17", "83"), options.toSet())
        assertEquals("choices must be distinct", options.size, options.distinct().size)
    }

    @Test
    fun returnsNullWithoutACompleteServerSuppliedChoiceSet() {
        assertNull("no digits at all", MfaNumberMatch.optionsFor("", listOf("17", "83")))
        assertNull("no decoys", MfaNumberMatch.optionsFor("42", emptyList()))
        assertNull("one decoy", MfaNumberMatch.optionsFor("42", listOf("17")))
        assertNull("decoys are all the answer", MfaNumberMatch.optionsFor("42", listOf("42", "42")))
        assertNull("too many decoys", MfaNumberMatch.optionsFor("42", listOf("17", "83", "91")))
    }

    @Test
    fun doesNotFabricateMissingDecoys() {
        assertNull(MfaNumberMatch.optionsFor("42", listOf("17")))
    }

    @Test
    fun dropsDuplicateAndAnswerEqualDecoys() {
        val options = MfaNumberMatch.optionsFor("42", listOf("17", "17", "83", "42"), noShuffle)

        assertEquals(MfaNumberMatch.CHOICE_COUNT, options!!.size)
        assertEquals("42 must appear exactly once", 1, options.count { it == "42" })
        assertEquals(setOf("42", "17", "83"), options.toSet())
    }

    @Test
    fun acceptsWhateverDigitWidthTheServerUsed() {
        assertNotNull(MfaNumberMatch.optionsFor("047", listOf("128", "935")))
        assertNotNull(MfaNumberMatch.optionsFor("7", listOf("2", "9")))
        assertEquals(
            setOf("047", "128", "935"),
            MfaNumberMatch.optionsFor("047", listOf("128", "935"))!!.toSet(),
        )
    }

    @Test
    fun rejectsDecoysOfADifferentWidth() {
        assertNull(MfaNumberMatch.optionsFor("42", listOf("173", "83")))
    }

    @Test
    fun rejectsNonDigits() {
        assertNull(MfaNumberMatch.optionsFor("4a", listOf("17", "83")))
    }

    @Test
    fun randomisesWhereTheAnswerLands() {
        val positions = (1..200)
            .map { MfaNumberMatch.optionsFor("42", listOf("17", "83"))!!.indexOf("42") }
            .toSet()

        assertTrue("the answer only ever landed at $positions — that is a free guess", positions.size > 1)
    }

    @Test
    fun alwaysReturnsEveryValueWhateverTheOrder() {
        repeat(50) {
            val options = MfaNumberMatch.optionsFor("42", listOf("17", "83"))!!
            assertEquals(setOf("42", "17", "83"), options.toSet())
        }
    }
}
