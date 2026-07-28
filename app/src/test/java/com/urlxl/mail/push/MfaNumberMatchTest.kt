package com.urlxl.mail.push

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

    /**
     * The whole control. A challenge without a full choice set cannot be approved, so the caller
     * gets null and must offer Deny only — not a bare Approve that sends no number, which the
     * server refuses while spending one of the challenge's three attempts.
     */
    @Test
    fun returnsNullWithoutACompleteServerSuppliedChoiceSet() {
        assertNull("no digits at all", MfaNumberMatch.optionsFor("", listOf("17", "83")))
        assertNull("no decoys", MfaNumberMatch.optionsFor("42", emptyList()))
        assertNull("one decoy", MfaNumberMatch.optionsFor("42", listOf("17")))
        assertNull("decoys are all the answer", MfaNumberMatch.optionsFor("42", listOf("42", "42")))
        assertNull("too many decoys", MfaNumberMatch.optionsFor("42", listOf("17", "83", "91")))
    }

    /** The client never invents a wrong answer. Decoys derived on-device from the challenge id were
     *  computable by anyone who knew the id. */
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

    /**
     * Width comes from the server, not a client constant. Two digits is only 100 values, so
     * widening it is the obvious next hardening — and pinning the width here would have made every
     * deployed client silently discard the field the moment the server did.
     */
    @Test
    fun acceptsWhateverDigitWidthTheServerUsed() {
        assertNotNull(MfaNumberMatch.optionsFor("047", listOf("128", "935")))
        assertNotNull(MfaNumberMatch.optionsFor("7", listOf("2", "9")))
        assertEquals(
            setOf("047", "128", "935"),
            MfaNumberMatch.optionsFor("047", listOf("128", "935"))!!.toSet(),
        )
    }

    /** Mixed widths are a malformed choice set, not a partial one — a tile that is visibly a
     *  different shape from the others is a free elimination. */
    @Test
    fun rejectsDecoysOfADifferentWidth() {
        assertNull(MfaNumberMatch.optionsFor("42", listOf("173", "83")))
    }

    @Test
    fun rejectsNonDigits() {
        assertNull(MfaNumberMatch.optionsFor("4a", listOf("17", "83")))
    }

    /** The answer must not sit in a predictable slot; that is a free guess for anyone who has seen
     *  the screen once. */
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
