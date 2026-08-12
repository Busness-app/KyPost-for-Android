package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * "Check again" is the only way forward from every state that stops with the keypair still live, so
 * a missing row here strands the user on a screen whose only other exit destroys the published key.
 * That is a JVM test rather than something visible only on a running screen.
 */
class OffersCheckAgainTest {

    private val code = EnrollmentUiState.ShowingCode("5R9K6FWA18A8YP", 1_000L)

    /**
     * The state a dismissed fingerprint prompt lands on. The envelope is already on the relay and
     * the keypair is what opens it, so this is precisely the state where resuming must be possible —
     * and it carries no code, so no other affordance on the screen can substitute for the button.
     */
    @Test
    fun aDismissedPromptCanBeResumed() {
        assertTrue(offersCheckAgain(EnrollmentUiState.ReadyToFinish, idle = true))
    }

    /** A window is still running behind the code; it will find the envelope on its own. */
    @Test
    fun aLiveWindowDoesNotOfferIt() {
        assertFalse(offersCheckAgain(code, idle = false))
    }

    /**
     * Defensive, and deliberately kept. A window that ends normally emits `WaitingTimedOut`, and the
     * cancelled prompt now lands on `ReadyToFinish`, so no designed path rests here — but a poll loop
     * that unwinds on a throw leaves the last emitted state as `ShowingCode` with `run()`'s `finally`
     * having set idle. Offering the button is the only way forward from that; the alternative is a
     * screen whose sole exit destroys a published key.
     */
    @Test
    fun aCodeLeftWithNoWindowBehindItOffersIt() {
        assertTrue(offersCheckAgain(code, idle = true))
    }

    @Test
    fun aTimedOutWindowOffersIt() {
        assertTrue(offersCheckAgain(EnrollmentUiState.WaitingTimedOut("5R9K6FWA18A8YP", 1_000L), idle = true))
    }

    /**
     * Terminal and transient states must not. Enrolled and Failed have both destroyed the keypair,
     * so "Check again" would resume against a key that no longer exists.
     */
    @Test
    fun spentAndTransientStatesDoNotOfferIt() {
        listOf(
            EnrollmentUiState.Enrolled,
            EnrollmentUiState.Failed(FailureReason.SEAL_FAILED),
            EnrollmentUiState.Unavailable(UnavailableReason.NOT_PAIRED),
            EnrollmentUiState.CheckingIdentity,
            EnrollmentUiState.PublishingKey,
            EnrollmentUiState.Opening,
            EnrollmentUiState.AwaitingAuth,
        ).forEach {
            assertFalse("$it must not offer Check again", offersCheckAgain(it, idle = true))
        }
    }
}
