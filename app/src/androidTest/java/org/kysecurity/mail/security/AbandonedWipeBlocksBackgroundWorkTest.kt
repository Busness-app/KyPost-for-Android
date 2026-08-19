package org.kysecurity.mail.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.testing.TestListenableWorkerBuilder
import androidx.work.testing.WorkManagerTestInitHelper
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The abandoned-wipe guard on the paths with no screen; LockedActivity only covers Activities. */
@RunWith(AndroidJUnit4::class)
class AbandonedWipeBlocksBackgroundWorkTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private fun wipeStatePrefs() =
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", Context.MODE_PRIVATE)

    /** Keys mirror SecurityWipe's private constants; each test's precondition catches a rename. */
    private fun markAbandoned() {
        wipeStatePrefs().edit()
            .putBoolean("wipe_in_progress", true)
            .putBoolean("wipe_abandoned", true)
            .putStringSet("wipe_failed_steps", setOf("sharedPrefs"))
            .commit()
    }

    @Before
    fun setUp() {
        wipeStatePrefs().edit().clear().commit()
        // An executor that never runs anything: these tests drive workers directly and assert on
        // what is enqueued, and letting WorkManager run the real ones would make live, credentialed
        // network calls from a test.
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().setExecutor { }.build(),
        )
    }

    @After
    fun tearDown() {
        wipeStatePrefs().edit().clear().commit()
    }

    @Test
    fun theGuardIsOffUntilAWipeIsActuallyAbandoned() {
        assertFalse(
            "a clean install must not be treated as blocked",
            SecurityWipe.blockedByAbandonedWipe(context),
        )

        // An interrupted-but-still-resumable wipe is NOT the terminal state. Conflating them would
        // brick the app on the ordinary case the resume exists to handle.
        wipeStatePrefs().edit().putBoolean("wipe_in_progress", true).commit()
        assertFalse(
            "a resumable wipe must not trip the terminal block",
            SecurityWipe.blockedByAbandonedWipe(context),
        )

        markAbandoned()
        assertTrue(
            "an abandoned wipe must trip the terminal block",
            SecurityWipe.blockedByAbandonedWipe(context),
        )
    }

    /** Cancels rather than skips: the periodic work is already enqueued and must not fire again. */
    @Test
    fun pullWorker_cancelsItselfInsteadOfPolling(): Unit = runBlocking {
        org.kysecurity.mail.push.PullScheduler.ensurePeriodic(context)
        assertTrue(
            "precondition: the periodic pull is enqueued",
            uniqueWorkIsLive("kypost_pull_periodic"),
        )
        markAbandoned()
        assertTrue("precondition: the guard is armed", SecurityWipe.blockedByAbandonedWipe(context))

        val result = TestListenableWorkerBuilder<org.kysecurity.mail.push.PullWorker>(context)
            .build()
            .doWork()

        assertEquals(androidx.work.ListenableWorker.Result.success(), result)
        assertFalse(
            "the periodic pull must be cancelled, not left to fire again in 15 minutes",
            uniqueWorkIsLive("kypost_pull_periodic"),
        )
    }

    /** The contacts provider is outside the sandbox, where no sandbox deletion reaches. */
    @Test
    fun deviceContactSyncWorker_cancelsItselfInsteadOfWritingContacts(): Unit = runBlocking {
        markAbandoned()
        assertTrue("precondition: the guard is armed", SecurityWipe.blockedByAbandonedWipe(context))

        val result =
            TestListenableWorkerBuilder<org.kysecurity.mail.contacts.device.DeviceContactSyncWorker>(context)
                .build()
                .doWork()

        assertEquals(androidx.work.ListenableWorker.Result.success(), result)
        assertFalse(
            "the periodic contact sync must be cancelled",
            uniqueWorkIsLive("kypost_device_contact_sync_periodic"),
        )
    }

    /** Reporting this device's key material to the server is a claim the app has no business
     *  making on a device it failed to erase. */
    @Test
    fun enrollmentStateWorker_reportsNothing(): Unit = runBlocking {
        markAbandoned()
        assertTrue("precondition: the guard is armed", SecurityWipe.blockedByAbandonedWipe(context))

        val result =
            TestListenableWorkerBuilder<org.kysecurity.mail.pgp.EnrollmentStateWorker>(context)
                .build()
                .doWork()

        assertEquals(androidx.work.ListenableWorker.Result.success(), result)
    }

    private fun uniqueWorkIsLive(name: String): Boolean =
        WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(name).get()
            .any { it.state == WorkInfo.State.ENQUEUED || it.state == WorkInfo.State.RUNNING }
}
