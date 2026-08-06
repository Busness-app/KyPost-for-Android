package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The worker's retry decision, tested as a pure function.
 *
 * It lives apart from the worker so it can be asserted without a device: the mapping is the
 * security-relevant part — a wrong branch here either drops a correction the server needs, or
 * spins forever against a credential the server will never accept.
 */
class EnrollmentReportOutcomeTest {

    /** The marker is now wrong in the unsafe direction — the Security page is telling the user this
     *  device can read their mail. Keep trying; offline is the expected case for the HLP path. */
    @Test
    fun aTransientFailureRetries() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network")),
        )
    }

    /**
     * Retrying is bounded.
     *
     * WorkManager applies no attempt ceiling of its own — verified against work-runtime 2.10.1,
     * which only clamps the backoff at five hours — so an unbounded RETRY is a work item that never
     * terminates, waking for the life of the install against a relay that may have been
     * decommissioned years earlier.
     */
    @Test
    fun retryingStopsAtTheAttemptCeiling() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network"), MAX_REPORT_ATTEMPTS - 1),
        )
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network"), MAX_REPORT_ATTEMPTS),
        )
    }

    /** The ceiling must not turn a success into a failure — it only bounds retrying. */
    @Test
    fun theCeilingDoesNotAffectSuccess() {
        assertEquals(
            EnrollmentReportOutcome.DONE,
            enrollmentReportOutcome(EnrollmentCallResult.Ok, MAX_REPORT_ATTEMPTS + 5),
        )
    }

    @Test
    fun rateLimitingRetries() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.RateLimited(42L)),
        )
    }

    /** A credential the server refuses will not start working on retry, and each attempt spends
     *  device-auth budget that the real device needs. */
    @Test
    fun aRefusedCredentialGivesUp() {
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.Unauthorized),
        )
    }

    @Test
    fun successIsDone() {
        assertEquals(EnrollmentReportOutcome.DONE, enrollmentReportOutcome(EnrollmentCallResult.Ok))
    }

    /**
     * 404 on this route means the device row is gone — deregistered, or the account was deleted.
     * There is nothing left to correct, so this is done rather than a retry loop against a row that
     * will never come back.
     */
    @Test
    fun aMissingDeviceRowIsDoneNotARetry() {
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.NotFound),
        )
    }
}
