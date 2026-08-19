package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** Pure arithmetic; see [expiryCountdown]'s KDoc for why `nowMs` is a parameter. */
class EnrollmentCountdownTest {

    @Test
    fun comfortablyPositiveCounts() {
        assertEquals(ExpiryCountdown.Counting(5), expiryCountdown(expiresAtEpochMs = 10_000L, nowMs = 4_500L))
    }

    @Test
    fun exactlyOneSecondCounts() {
        assertEquals(ExpiryCountdown.Counting(1), expiryCountdown(expiresAtEpochMs = 5_000L, nowMs = 4_000L))
    }

    @Test
    fun exactlyZeroIsNow() {
        assertEquals(ExpiryCountdown.Now, expiryCountdown(expiresAtEpochMs = 5_000L, nowMs = 5_000L))
    }

    @Test
    fun alreadyPastIsNow() {
        assertEquals(ExpiryCountdown.Now, expiryCountdown(expiresAtEpochMs = 5_000L, nowMs = 9_000L))
    }
}
