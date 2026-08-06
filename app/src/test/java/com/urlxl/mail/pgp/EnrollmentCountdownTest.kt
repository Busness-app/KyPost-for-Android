package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The countdown's pure arithmetic — see [expiryCountdown]'s KDoc for why `nowMs` is a parameter
 * rather than a clock read internally.
 *
 * Comfortably positive, exactly 1, exactly 0, and already-past are the four cases a fix-round
 * review asked this extraction to cover. Exactly 1 is also the case that would, on its own, have
 * caught "This code changes in 1 seconds." — the `enrollment_code_expiry` string rendered through
 * `getString` instead of `getQuantityString` before it became a `<plurals>` resource — since a
 * test asserting `remainingSeconds == 1` forces a look at what actually renders it.
 */
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
