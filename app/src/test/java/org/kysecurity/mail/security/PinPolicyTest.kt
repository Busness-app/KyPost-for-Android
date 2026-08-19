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
}
