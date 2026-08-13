package org.kysecurity.mail.contacts.device

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

class DeviceContactSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val graph = DeviceContactsRuntime.graph(applicationContext)
        // This worker calls the repository directly rather than going through the coordinator, so
        // the coordinator's Hostile Location Protection veto has to be repeated here — an already
        // enqueued periodic run would otherwise keep writing contacts to the OS provider after
        // protection was turned on.
        // Same shape as the protection veto below, and for a stronger reason: after an abandoned
        // wipe this worker would write the account's contacts back into the OS provider — outside
        // this app's sandbox — on a device the wipe had just tried to remove them from.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("DeviceContactSyncWorker", "Cancelling sync: a previous wipe was abandoned")
            DeviceContactSyncScheduler.cancelPeriodic(applicationContext)
            return Result.success()
        }
        if (!graph.syncPermitted() || !graph.settings.isEnabled()) {
            DeviceContactSyncScheduler.cancelPeriodic(applicationContext)
            return Result.success()
        }
        return try {
            graph.repository.syncAll()
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}

object DeviceContactSyncScheduler {
    private const val PERIODIC_WORK_NAME = "kypost_device_contact_sync_periodic"
    private const val PERIOD_MINUTES = 15L

    fun ensurePeriodic(context: Context) {
        val request = PeriodicWorkRequestBuilder<DeviceContactSyncWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    fun cancelPeriodic(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(PERIODIC_WORK_NAME)
    }
}
