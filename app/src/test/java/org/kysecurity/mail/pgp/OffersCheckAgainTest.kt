package org.kysecurity.mail.pgp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The only way forward from every state that stops with the keypair still live. */
class OffersCheckAgainTest {

    private val code = EnrollmentUiState.ShowingCode("5R9K6FWA18A8YP", 1_000L)

    /** `ReadyToFinish` carries no code, so no other affordance can substitute for the button. */
    @Test
    fun aDismissedPromptCanBeResumed() {
        assertTrue(offersCheckAgain(EnrollmentUiState.ReadyToFinish, idle = true))
    }

    /** A window is still running behind the code; it will find the envelope on its own. */
    @Test
    fun aLiveWindowDoesNotOfferIt() {
        assertFalse(offersCheckAgain(code, idle = false))
    }

    /** Defensive: no designed path rests here, but a poll loop unwinding on a throw does. */
    @Test
    fun aCodeLeftWithNoWindowBehindItOffersIt() {
        assertTrue(offersCheckAgain(code, idle = true))
    }

    @Test
    fun aTimedOutWindowOffersIt() {
        assertTrue(offersCheckAgain(EnrollmentUiState.WaitingTimedOut("5R9K6FWA18A8YP", 1_000L), idle = true))
    }

    /** Enrolled and Failed have both destroyed the keypair. */
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
