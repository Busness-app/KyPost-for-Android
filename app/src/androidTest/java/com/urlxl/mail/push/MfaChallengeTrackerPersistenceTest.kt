package com.urlxl.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The tracker's storage half. It used to be a process-lifetime `ConcurrentHashMap`, which was
 * usually already gone by the time the user tapped the notification: FCM delivers to a
 * freshly-started process and Android kills it again moments later, so a legitimate tap fell
 * through to the inbox with no explanation while the sign-in timed out.
 */
@RunWith(AndroidJUnit4::class)
class MfaChallengeTrackerPersistenceTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun newTracker() = MfaChallengeTracker(context)

    @Test
    fun aDeliveredChallengeSurvivesANewTrackerInstance() {
        val id = "challenge-${System.nanoTime()}"
        newTracker().markDelivered(id)

        // A separate instance stands in for the next process: the record has to outlive the one
        // that wrote it.
        assertTrue(newTracker().isPending(id))
    }

    @Test
    fun anUndeliveredChallengeIsNeverPending() {
        // The anti-spoofing property: MainActivity is exported, so extras alone must not be enough
        // to surface the approval screen.
        assertFalse(newTracker().isPending("never-delivered-${System.nanoTime()}"))
    }

    @Test
    fun aBlankChallengeIdIsNeverPending() {
        assertFalse(newTracker().isPending(""))
    }

    @Test
    fun clearMakesAChallengeUnanswerableAgain() {
        val id = "challenge-${System.nanoTime()}"
        val tracker = newTracker()
        tracker.markDelivered(id)
        assertTrue(tracker.isPending(id))

        tracker.clear(id)

        // Answered once, answerable once — a replayed notification tap must not re-open a decision
        // the user already made.
        assertFalse(newTracker().isPending(id))
    }

    @Test
    fun anExpiredChallengeIsNotPending() {
        val id = "challenge-${System.nanoTime()}"
        val now = System.currentTimeMillis()
        newTracker().markDelivered(id, nowEpochMs = now - (6 * 60 * 1000L))

        assertFalse(newTracker().isPending(id, nowEpochMs = now))
    }
}
