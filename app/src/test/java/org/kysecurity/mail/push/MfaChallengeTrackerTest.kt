package org.kysecurity.mail.push

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Freshness only; storage is covered by instrumented MfaChallengeTrackerPersistenceTest. */
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

    /** The cap has to leave room for more than one genuine sign-in in flight while still being a
     *  cap — a relay minting challenges faster than the user can answer them is the attack. */
    @Test
    fun theTrackedChallengeCapIsSmallButNotOne() {
        assertTrue(MAX_TRACKED_CHALLENGES in 2..32)
    }
}
