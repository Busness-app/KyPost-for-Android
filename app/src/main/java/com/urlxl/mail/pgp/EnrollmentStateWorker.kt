package com.urlxl.mail.pgp

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.urlxl.mail.push.PushRuntime
import java.util.concurrent.TimeUnit

/** What to do after one attempt at reporting. Kept apart from `ListenableWorker.Result` so the
 *  decision can be asserted on the JVM, without a device. */
internal enum class EnrollmentReportOutcome { DONE, RETRY, GIVE_UP }

/**
 * Whether a failed report is worth another attempt.
 *
 * Retry is the answer whenever the server's marker is wrong in the *unsafe* direction — the
 * Security page telling the user this device can read their mail after the envelope is gone. Give
 * up only where another attempt cannot change the answer: a credential the server refuses will not
 * start working, and a device row that is gone will not come back.
 */
internal fun enrollmentReportOutcome(result: EnrollmentCallResult): EnrollmentReportOutcome =
    when (result) {
        is EnrollmentCallResult.Ok -> EnrollmentReportOutcome.DONE
        is EnrollmentCallResult.RateLimited, is EnrollmentCallResult.Failed -> EnrollmentReportOutcome.RETRY
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
        // Read at run time, never carried in inputData: WorkManager writes input to its own
        // database in plaintext, and this is the credential every authenticated call uses.
        val pairing = PushRuntime.graph(applicationContext).securePairingStore.pairingSnapshot(null)
            // Unpaired: there is no device row left to correct. SecurityWipe's path lands here.
            ?: return Result.success()
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Paired, but the secret is wrapped under the credential gate and this process has not
            // been PIN-unlocked. Distinct from unpaired, and a retry rather than a success: the
            // report is still owed and a later run, after an unlock, can deliver it. Treating it as
            // success would leave the server saying this device can read mail it can no longer open.
            return Result.retry()
        }

        val enrolled = probeEnrollment(EnrollmentVault(applicationContext)).isEnrolled()

        val result = EnrollmentClients().reportState(pairing.serverUrl, deviceId, deviceSecret, enrolled)
        return when (enrollmentReportOutcome(result)) {
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
