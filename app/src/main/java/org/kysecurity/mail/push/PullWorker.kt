package org.kysecurity.mail.push

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Battery-friendly baseline poller for "App Pull" mode.
 *
 * Tradeoff: pull mode has no FCM push to wake us, so we can't get true real-time delivery
 * for free. We use WorkManager periodic work at the platform minimum (15 min) plus an
 * immediate pull on every app foreground ([KyPostApp]) and after (re)pairing. This keeps
 * background battery cost negligible at the price of up to ~15 min latency while backgrounded.
 * If near-real-time background delivery is ever required, the alternative is a foreground
 * service with a 30–60s poll loop and a persistent notification, gated behind a user setting —
 * deliberately NOT the default here.
 */
class PullWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val graph = PushRuntime.graph(applicationContext)
        return when (graph.pullCoordinator.pullOnce()) {
            // Transient server/network failure — let WorkManager back off exponentially.
            is PullOutcome.Retry -> Result.retry()
            // Everything else (pulled, not paired, wrong mode, 400/401) is terminal for this run;
            // the next periodic tick re-evaluates. 401 must not tight-loop, so never retry it here.
            else -> Result.success()
        }
    }
}

object PullScheduler {
    private const val PERIODIC_WORK_NAME = "kypost_pull_periodic"

    // WorkManager's hard floor for periodic work; documented as the baseline pull cadence.
    private const val PERIOD_MINUTES = 15L

    fun ensurePeriodic(context: Context) {
        val request = PeriodicWorkRequestBuilder<PullWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            // KEEP: don't reset the schedule (or its backoff) every time we re-arm.
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    fun cancelPeriodic(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(PERIODIC_WORK_NAME)
    }
}
