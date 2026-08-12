package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LockoutPolicyTest {
    @Test
    fun delayMillisFor_isZero_forFirstTwoAttempts() {
        assertEquals(0L, LockoutPolicy.delayMillisFor(1))
        assertEquals(0L, LockoutPolicy.delayMillisFor(2))
    }

    @Test
    fun delayMillisFor_escalates_fromThirdAttempt() {
        assertEquals(30_000L, LockoutPolicy.delayMillisFor(3))
        assertEquals(60_000L, LockoutPolicy.delayMillisFor(4))
        assertEquals(300_000L, LockoutPolicy.delayMillisFor(5))
        assertEquals(900_000L, LockoutPolicy.delayMillisFor(6))
        assertEquals(1_800_000L, LockoutPolicy.delayMillisFor(7))
    }

    @Test
    fun delayMillisFor_caps_atThirtyMinutes() {
        assertEquals(1_800_000L, LockoutPolicy.delayMillisFor(8))
        assertEquals(1_800_000L, LockoutPolicy.delayMillisFor(9))
    }

    @Test
    fun shouldWipe_isFalse_belowThreshold() {
        assertFalse(LockoutPolicy.shouldWipe(9))
    }

    @Test
    fun shouldWipe_isTrue_atThreshold() {
        assertTrue(LockoutPolicy.shouldWipe(10))
        assertTrue(LockoutPolicy.shouldWipe(11))
    }
}
