package com.urlxl.mail.security

import org.junit.Assert.assertEquals
import org.junit.Test

class PinPolicyTest {

    @Test
    fun acceptsAnUnremarkablePinAtTheMinimumLength() {
        assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("48291374"))
    }

    @Test
    fun acceptsLongerPins() {
        // The old flow hardcoded exactly 6; length is the only lever the user has against the
        // keyspace, so a longer PIN must not be rejected.
        assertEquals(PinPolicy.Result.Valid, PinPolicy.validate("4829137056"))
    }

    @Test
    fun rejectsShortAndOverlongPins() {
        // 6 and 7 digits were accepted before the minimum was raised: PBKDF2 iterations cannot
        // defend a 10^6 keyspace, so the floor moved rather than the iteration count.
        assertEquals(PinPolicy.Result.TooShort, PinPolicy.validate("482913"))
        assertEquals(PinPolicy.Result.TooShort, PinPolicy.validate("4829137"))
        assertEquals(PinPolicy.Result.TooLong, PinPolicy.validate("4829137056482913"))
    }

    @Test
    fun rejectsNonDigits() {
        assertEquals(PinPolicy.Result.NotNumeric, PinPolicy.validate("48a91374"))
    }

    @Test
    fun rejectsTheCommonPinsThatTenGuessesWouldCover() {
        // The lock wipes after 10 wrong attempts, so an attacker gets ten tries — every one of
        // these would have been inside that budget.
        listOf("12121212", "11223344", "12341234", "19801980", "14725836").forEach {
            assertEquals("expected $it to be rejected", PinPolicy.Result.TooCommon, PinPolicy.validate(it))
        }
    }

    @Test
    fun rejectsRunsTooLongToEnumerateInTheFixedList() {
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("23456789"))
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("98765432"))
        assertEquals(PinPolicy.Result.TooCommon, PinPolicy.validate("55555555"))
    }

    /** Guards against the blocklist silently becoming dead code again: every entry has to be long
     *  enough to survive the length check that runs before it. */
    @Test
    fun everyBlockedPinIsReachableGivenTheMinimumLength() {
        listOf("12121212", "19701970", "78945612").forEach {
            assertEquals("expected $it to reach the blocklist", PinPolicy.Result.TooCommon, PinPolicy.validate(it))
        }
    }
}
