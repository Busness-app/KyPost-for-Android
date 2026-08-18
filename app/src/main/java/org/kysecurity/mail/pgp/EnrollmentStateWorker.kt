package org.kysecurity.mail.pgp

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import java.util.concurrent.TimeUnit

/** What to do after one attempt at reporting. Kept apart from `ListenableWorker.Result` so the
 *  decision can be asserted on the JVM, without a device. */
internal enum class EnrollmentReportOutcome { DONE, RETRY, GIVE_UP }

/**
 * How many times a report may be retried before it is abandoned.
 *
 * WorkManager imposes no ceiling of its own — it only clamps the exponential backoff at five hours —
 * so a RETRY with no bound is a work item that never terminates. With the 30-second base delay this
 * spans roughly a day and a half of real attempts, which is generous for "the network came back"
 * and finite for "this relay is never answering again".
 */
internal const val MAX_REPORT_ATTEMPTS = 8

/**
 * Whether a failed report is worth another attempt.
 *
 * Retry is the answer whenever the server's marker is wrong in the *unsafe* direction — the
 * Security page telling the user this device can read their mail after the envelope is gone. Give
 * up only where another attempt cannot change the answer: a credential the server refuses will not
 * start working, a device row that is gone will not come back, and past [MAX_REPORT_ATTEMPTS] the
 * evidence is that nothing is going to.
 */
internal fun enrollmentReportOutcome(
    result: EnrollmentCallResult,
    runAttemptCount: Int = 0,
): EnrollmentReportOutcome =
    when (result) {
        is EnrollmentCallResult.Ok -> EnrollmentReportOutcome.DONE
        is EnrollmentCallResult.RateLimited, is EnrollmentCallResult.Failed ->
            if (runAttemptCount >= MAX_REPORT_ATTEMPTS) EnrollmentReportOutcome.GIVE_UP
            else EnrollmentReportOutcome.RETRY
        is EnrollmentCallResult.Unauthorized, is EnrollmentCallResult.NotFound -> EnrollmentReportOutcome.GIVE_UP
        // Only fetchEnvelope produces this; reportState cannot. Not a retry: a response this route
        // has no way to send means the client is talking to something that is not this API.
        is EnrollmentCallResult.Envelope -> EnrollmentReportOutcome.GIVE_UP
    }

/**
 * Reports enrollment state durably.
 *
 * Enqueued before Hostile Location Protection's flag flips, so an interrupted teardown still
 * corrects the server: the Security page would otherwise show this device as protected in the
 * window between, which is the specific lie the marker exists to prevent. Offline is the expected
 * case — the user just declared they are somewhere hostile — so this retries rather than dropping.
 */
internal class EnrollmentStateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Before the credential is even read. This worker exists to tell the server what key
        // material this device holds; after an abandoned wipe that is a claim the app has no
        // business making, on a device it failed to erase.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("EnrollmentStateWorker", "Skipping state report: a previous wipe was abandoned")
            return Result.success()
        }

        // Read at run time, never carried in inputData: WorkManager writes input to its own
        // database in plaintext, and this is the credential every authenticated call uses.
        //
        val pairing = PushRuntime.graph(applicationContext).repository.pairingForAuthenticatedCall()
            // Unpaired: there is no device row left to correct. SecurityWipe's path lands here.
            ?: return Result.success()
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Gated and currently locked, so the secret cannot be unwrapped in this run. Retrying
            // cannot help — only a PIN unlock can, and the unlock path re-enqueues us (see
            // UnlockActivity). Succeeding here releases the work slot instead of occupying it with
            // a job that can never make progress.
            return Result.success()
        }

        val enrolled = probeEnrollment(EnrollmentVault(applicationContext)).isEnrolled()

        // The pinned factory, exactly as every other client that carries the device credential does.
        // The bare default was unpinned, which made this the only credentialed request in the app
        // outside the TOFU pin — and the only thing that triggers it is the user declaring the
        // network hostile, which is the worst possible moment to be trusting the system CA set.
        val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(applicationContext))
        val result = clients.reportState(pairing.serverUrl, deviceId, deviceSecret, enrolled)
        return when (enrollmentReportOutcome(result, runAttemptCount)) {
            EnrollmentReportOutcome.DONE -> Result.success()
            EnrollmentReportOutcome.RETRY -> Result.retry()
            EnrollmentReportOutcome.GIVE_UP -> Result.failure()
        }
    }

    companion object {
        const val UNIQUE_NAME = "kypost_enrollment_state_report"

        /** Separate from [enqueue] so a test can read what would be enqueued without a scheduler
         *  running it. The request carries no input data; see [doWork]. */
        @VisibleForTesting
        internal fun buildRequest(): OneTimeWorkRequest =
            OneTimeWorkRequestBuilder<EnrollmentStateWorker>()
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()

        fun enqueue(context: Context) {
            WorkManager.getInstance(context.applicationContext)
                // REPLACE, not KEEP: the worker re-probes live state on every run, so the newest
                // request is always the truthful one and a stale pending report is worth nothing.
                .enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.REPLACE, buildRequest())
        }
    }
}
