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

/**
 * [SecurityWipe.blockedByAbandonedWipe] and the background entry points that depend on it.
 *
 * [LockedActivity]'s terminal block covers Activities, and only Activities. It was the whole
 * enforcement of the abandoned-wipe state, which left the paths that need no screen wide open —
 * and those are the ones that matter most, because an abandoned wipe very often leaves the pairing
 * credential on disk (`sharedPrefs` is the step that holds it, and one of the likelier ones to
 * fail). Push kept arriving, the pull worker kept fetching mail metadata and rendering sender and
 * subject as notifications, the contact worker kept writing the account's contacts back into the
 * OS provider, and a token refresh would have minted a **fresh** device secret — re-arming exactly
 * the access the wipe was trying to revoke.
 *
 * These assert the guard flips correctly and that the workers act on it. The push services take
 * the same guard on their first line; there is no way to deliver a real `RemoteMessage` from a
 * test, so those are covered by the shared predicate here rather than end to end.
 */
@RunWith(AndroidJUnit4::class)
class AbandonedWipeBlocksBackgroundWorkTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private fun wipeStatePrefs() =
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", Context.MODE_PRIVATE)

    /**
     * Puts the app in the terminal state directly rather than by failing three real wipes, which
     * would take minutes and destroy unrelated fixtures.
     *
     * The keys mirror `SecurityWipe`'s private constants, so this could rot into writing
     * meaningless preferences that leave the guard false and pass every assertion below for the
     * wrong reason. That is what the precondition in each test is for: it asserts the *production*
     * predicate agrees, so a rename fails here loudly instead of silently disarming the suite.
     */
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

    /**
     * The pull worker is what turns a surviving credential into live mail metadata on the lock
     * screen. Cancelling, not merely skipping: the periodic work is already enqueued, and nothing
     * in a blocked app will legitimately want it back before a reinstall.
     */
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

    /**
     * The contact worker writes to the OS contacts provider — outside this app's sandbox, where no
     * sandbox deletion reaches. Re-populating it after a failed wipe undoes the one step of the
     * wipe the user cannot clean up themselves by uninstalling.
     */
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
