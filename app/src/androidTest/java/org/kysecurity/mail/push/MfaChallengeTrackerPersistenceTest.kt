package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Persisted, not in-memory: the FCM process usually dies before the user taps. */
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

    /** markDelivered rebuilds the whole file, so an unserialised clear can be silently undone. */
    @Test
    fun aClearedChallengeIsNotResurrectedByAConcurrentDelivery() {
        repeat(30) { round ->
            val answered = "answered-$round-${System.nanoTime()}"
            val arriving = "arriving-$round-${System.nanoTime()}"
            newTracker().markDelivered(answered)
            assertTrue(newTracker().isPending(answered))

            // The two operations that raced: one thread answering a challenge, another taking
            // delivery of the next one in the flood.
            val clearer = Thread { newTracker().clear(answered) }
            val deliverer = Thread { newTracker().markDelivered(arriving) }
            clearer.start()
            deliverer.start()
            clearer.join()
            deliverer.join()

            assertFalse(
                "Cleared challenge $answered came back after a concurrent delivery",
                newTracker().isPending(answered),
            )
            assertTrue(newTracker().isPending(arriving))
        }
    }

    /** The cooldown shares this file so it survives the FCM-driven process churn. */
    @Test
    fun theAlertCooldownSurvivesANewTrackerInstanceAndOtherDeliveries() {
        val cooldownMs = 5 * 60 * 1000L
        // Reset the window by consuming whatever a previous test left, then take the alert.
        newTracker().shouldSuppressAlert(cooldownMs)

        assertTrue(newTracker().shouldSuppressAlert(cooldownMs).suppress)

        // An unrelated delivery rewrites the whole file; the cooldown must be carried across it.
        newTracker().markDelivered("cooldown-probe-${System.nanoTime()}")
        assertTrue(newTracker().shouldSuppressAlert(cooldownMs).suppress)
    }

    @Test
    fun restoringTheCooldownReopensTheAlertWindow() {
        val cooldownMs = 5 * 60 * 1000L
        val now = System.currentTimeMillis()
        // Explicit starting point and explicit clock: these tests share one preferences file, so
        // "no alert has been taken yet" has to be established rather than assumed.
        newTracker().restoreAlertCooldown(0L)

        val first = newTracker().shouldSuppressAlert(cooldownMs, now)
        assertFalse(first.suppress)
        assertTrue(newTracker().shouldSuppressAlert(cooldownMs, now + 1_000L).suppress)

        // The notification never reached the shade, so the window has to reopen — otherwise one
        // revoked permission silences five minutes of sign-in prompts the user would have seen.
        newTracker().restoreAlertCooldown(first.previousAlertAtEpochMs)

        assertFalse(newTracker().shouldSuppressAlert(cooldownMs, now + 1_000L).suppress)
    }
}
