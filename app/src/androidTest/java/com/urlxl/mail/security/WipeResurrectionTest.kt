package com.urlxl.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PairingData
import com.urlxl.mail.push.PushRuntime
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Regression tests for [SecurityWipe]'s ordering and its resume bookkeeping.
 *
 * Each of these began as an audit probe asserting a defect; they now assert the contract the fixes
 * established. The wipe runs precisely when the device is presumed hostile, so "what is still on
 * disk afterwards" and "what the app then tells the user" are both security properties.
 */
@RunWith(AndroidJUnit4::class)
class WipeResurrectionTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    private fun dbFile() = context.getDatabasePath("kypost_mail.db")
    private fun pushStateFile() = File(context.filesDir, "datastore/push_state.preferences_pb")
    private fun hostilePrefsFile() =
        File(File(context.dataDir, "shared_prefs"), "com.urlxl.mail.hostile_location_settings.xml")

    @Before
    fun clean() {
        context.getSharedPreferences("com.urlxl.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
        HostileLocationSettings(context).setEnabled(false)
        DataRuntime.invalidate()
        PushRuntime.invalidate()
        SecurityRuntime.invalidate()
    }

    /**
     * The wipe deletes `kypost_mail.db` early and must not rebuild it later.
     *
     * `clearPairingState` -> `purgeAccountScopedData` used to dereference `DataRuntime.graph(...)`,
     * which constructs a Room database — fifteen steps after the one that deleted it. It now reads
     * through `peekGraph()`, so an already-torn-down graph means nothing to purge.
     */
    @Test
    fun wipe_doesNotRecreateTheDatabaseFileItDeleted(): Unit = runBlocking {
        DataRuntime.graph(context).database.openHelper.writableDatabase
        assertTrue("precondition: db exists", dbFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(
            "kypost_mail.db must not be recreated by the wipe's own later steps",
            dbFile().exists(),
        )
    }

    /**
     * The same rebuild under Hostile Location Protection was worse: the flag deciding disk-vs-memory
     * had already been deleted by the `sharedPrefs` step, so the resurrected graph was DISK-backed —
     * a KyPost mail schema materialising on disk in the one mode that promises none.
     */
    @Test
    fun wipe_underHostileLocation_leavesNoDatabaseOnDisk(): Unit = runBlocking {
        HostileLocationSettings(context).setEnabled(true)
        DataRuntime.invalidate()
        SecurityRuntime.invalidate()
        PushRuntime.invalidate()
        context.deleteDatabase("kypost_mail.db")
        // In-memory graph, as the feature promises.
        DataRuntime.graph(context).database.openHelper.writableDatabase
        assertFalse("precondition: no db file under protection", dbFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertTrue("protection flag restored", HostileLocationSettings(context).isEnabled())
        assertFalse(
            "no disk-backed kypost_mail.db may exist after a wipe under Hostile Location Protection",
            dbFile().exists(),
        )
    }

    /**
     * A wipe force-stopped after `step("sharedPrefs")` leaves the protection flag file deleted and
     * the resume marker set. The resumed run must still restore the posture.
     *
     * It used to re-read the flag from the file the interrupted run had already deleted, get
     * `false`, and skip the restore permanently — so the user re-paired onto a disk-backed plaintext
     * database on a device the app had just decided was hostile. The posture is now recorded in the
     * retained `wipe_state` file at `markWipeInProgress` time.
     */
    @Test
    fun resumedWipe_restoresHostileLocationProtection(): Unit = runBlocking {
        HostileLocationSettings(context).setEnabled(true)
        assertTrue(HostileLocationSettings(context).isEnabled())

        // What the first, interrupted run left behind: marker set with the posture recorded, and the
        // prefs file already deleted.
        context.getSharedPreferences("com.urlxl.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("wipe_in_progress", true)
            .putBoolean("hostile_location_was_enabled", true)
            .putInt("wipe_attempts", 1)
            .commit()
        context.deleteSharedPreferences("com.urlxl.mail.hostile_location_settings")
        assertFalse(hostilePrefsFile().exists())
        assertTrue(SecurityWipe.wipeInterrupted(context))

        // Cold-start resume path.
        SecurityWipe.enforceTripwire(context)

        assertTrue(
            "Hostile Location Protection must survive a resumed wipe",
            HostileLocationSettings(context).isEnabled(),
        )
    }

    /**
     * `MAX_WIPE_RESUMES` must be a lifetime ceiling, not a rolling window.
     *
     * `clearWipeMarker()` used to `clear()` the whole file, dropping the attempt counter along with
     * the in-progress flag — so reaching the ceiling reset the budget to zero and the counter cycled
     * 1, 2, 0, 1, 2, 0, 1 forever. It now removes only the flag.
     */
    @Test
    fun wipeAttemptCeiling_accumulatesAcrossRuns(): Unit = runBlocking {
        val prefs = context.getSharedPreferences(
            "com.urlxl.mail.wipe_state", android.content.Context.MODE_PRIVATE,
        )
        val dir = File(context.dataDir, "shared_prefs")
        org.junit.Assume.assumeTrue(dir.exists() && dir.setReadable(false, false))
        try {
            val seen = mutableListOf<Int>()
            repeat(5) {
                SecurityWipe.wipeAndResetApp(context)
                seen += prefs.getInt("wipe_attempts", 0)
            }
            assertEquals(
                "the attempt count must climb monotonically, not reset at the ceiling",
                listOf(1, 2, 3, 4, 5),
                seen,
            )
        } finally {
            dir.setReadable(true, false)
        }
    }

    /**
     * Past the ceiling the wipe stops resuming, and says so: `willRetry` is what stops the UI
     * promising a retry on the one run that gave up.
     */
    @Test
    fun pastTheCeiling_theResultReportsThatNoRetryIsComing(): Unit = runBlocking {
        val dir = File(context.dataDir, "shared_prefs")
        org.junit.Assume.assumeTrue(dir.exists() && dir.setReadable(false, false))
        try {
            var last: WipeResult? = null
            repeat(4) { last = SecurityWipe.wipeAndResetApp(context) }
            val result = last
            assertTrue("a failing wipe must report Incomplete", result is WipeResult.Incomplete)
            assertFalse(
                "past MAX_WIPE_RESUMES the user must not be promised a retry",
                (result as WipeResult.Incomplete).willRetry,
            )
        } finally {
            dir.setReadable(true, false)
        }
    }

    /** The datastore holding the last 30 sender/subject pairs must actually be gone. */
    @Test
    fun wipe_deletesThePushHistoryDatastore(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        repo.appendPayload(
            com.urlxl.mail.push.PushPayload(
                messageId = "m1", senderName = "Sender X", emailSubject = "Subject Y",
                keywords = listOf("legal"), receivedAtEpochMs = 1L,
            ),
        )
        assertTrue("precondition: push_state written", pushStateFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse("push_state must not survive a wipe", pushStateFile().exists())
    }
}
