package com.urlxl.mail.push

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the freshness window only. The storage half moved to SharedPreferences (so a challenge
 * survives the process death that FCM delivery routinely causes) and is exercised by the
 * instrumented `MfaChallengeTrackerPersistenceTest`.
 */
class MfaChallengeTrackerTest {

    @Test
    fun freshImmediatelyAfterDelivery() {
        assertTrue(mfaChallengeIsFresh(deliveredAtEpochMs = 1_000L, nowEpochMs = 1_000L))
    }

    @Test
    fun staysFreshWithinFiveMinutes() {
        assertTrue(mfaChallengeIsFresh(deliveredAtEpochMs = 1_000L, nowEpochMs = 1_000L + 60_000L))
        assertTrue(mfaChallengeIsFresh(deliveredAtEpochMs = 1_000L, nowEpochMs = 1_000L + 5 * 60 * 1000L))
    }

    @Test
    fun expiresAfterFiveMinutes() {
        assertFalse(mfaChallengeIsFresh(deliveredAtEpochMs = 1_000L, nowEpochMs = 1_000L + 5 * 60 * 1000L + 1))
    }

    @Test
    fun aDeliveryTimestampInTheFutureIsNotFresh() {
        // A backwards clock jump must not read as "delivered moments ago", indefinitely.
        assertFalse(mfaChallengeIsFresh(deliveredAtEpochMs = 10_000L, nowEpochMs = 1_000L))
    }
}
