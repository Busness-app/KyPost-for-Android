package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Test

class PinPolicyTest {

    @Test
    fun acceptsAnUnremarkablePinAtTheMinimumLength() {
        assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("48291374".toCharArray()))
    }

    @Test
    fun acceptsLongerPins() {
        assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("4829137056".toCharArray()))
    }

    @Test
    fun rejectsShortAndOverlongPins() {
        assertEquals(PinPolicy.Result.TooShort, PinPolicy.validate("482913".toCharArray()))
        assertEquals(PinPolicy.Result.TooShort, PinPolicy.validate("4829137".toCharArray()))
        assertEquals(PinPolicy.Result.TooLong, PinPolicy.validate("4829137056482913".toCharArray()))
    }

    @Test
    fun rejectsNonDigits() {
        assertEquals(PinPolicy.Result.NotNumeric, PinPolicy.validate("48a91374".toCharArray()))
    }

    @Test
    fun rejectsTheCommonPinsThatTenGuessesWouldCover() {
        listOf("12121212", "11223344", "12341234", "19801980", "14725836").forEach {
            assertEquals("expected $it to be rejected", PinPolicy.Result.TooCommon, PinPolicy.validate(it.toCharArray()))
        }
    }

    @Test
    fun rejectsRunsTooLongToEnumerateInTheFixedList() {
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("23456789".toCharArray()))
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("98765432".toCharArray()))
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("55555555".toCharArray()))
    }

    /** Guards against the blocklist silently becoming dead code again: every entry has to be long
     *  enough to survive the length check that runs before it. */
    @Test
    fun everyBlockedPinIsReachableGivenTheMinimumLength() {
        listOf("12121212", "19701970", "78945612").forEach {
            assertEquals("expected $it to reach the blocklist", PinPolicy.Result.TooCommon, PinPolicy.validate(it.toCharArray()))
        }
    }

    /** `Char.isDigit()` is the Unicode Nd category, not ASCII, so these passed a check whose
     *  surrounding KDoc reasons about a 10^8 space — and [PinPolicy.isRun] subtracts code points,
     *  which means neither the stated cost to guess nor the run detection described the alphabet
     *  actually accepted. */
    @Test
    fun nonAsciiDigitsAreNotNumeric() {
        assertEquals(PinPolicy.Result.NotNumeric, PinPolicy.validate("\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667".toCharArray()))
        assertEquals(PinPolicy.Result.NotNumeric, PinPolicy.validate("\u0966\u0967\u0968\u0969\u096A\u096B\u096C\u096D".toCharArray()))
        // Mixed is still refused: one non-ASCII digit is enough.
        assertEquals(PinPolicy.Result.NotNumeric, PinPolicy.validate("4829137\u0660".toCharArray()))
    }

    @Test
    fun plainAsciiDigitsStillPass() {
        assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("48291374".toCharArray()))
    }
}
