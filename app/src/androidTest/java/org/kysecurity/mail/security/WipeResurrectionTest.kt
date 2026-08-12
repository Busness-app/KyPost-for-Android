package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime
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
        File(File(context.dataDir, "shared_prefs"), "org.kysecurity.mail.hostile_location_settings.xml")
    private fun ledgerFile() =
        File(File(context.dataDir, "shared_prefs"), "org.kysecurity.mail.downloaded_attachments.xml")

    /** True once the ledger's apply()-backed write has reached disk, or false after ~2s. */
    private fun awaitLedgerFile(): Boolean {
        repeat(40) {
            if (ledgerFile().exists()) return true
            Thread.sleep(50)
        }
        return false
    }

    @Before
    fun clean() {
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
        // The attachment ledger is deliberately retained across a wipe now, so an undeletable entry
        // left by one test would otherwise fail the next one's sweep.
        context.deleteSharedPreferences("org.kysecurity.mail.downloaded_attachments")
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
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("wipe_in_progress", true)
            .putBoolean("hostile_location_was_enabled", true)
            .putInt("wipe_attempts", 1)
            .commit()
        context.deleteSharedPreferences("org.kysecurity.mail.hostile_location_settings")
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
     * `MAX_WIPE_RESUMES` bounds ONE wipe's resumes. It is not a rolling window, and it is not a
     * lifetime budget either.
     *
     * Two bugs have lived here. First, `clearWipeMarker()` used to `clear()` the whole file, dropping
     * the attempt counter with the in-progress flag, so reaching the ceiling reset the budget and the
     * counter cycled 1, 2, 0, 1, 2, 0 forever — the ceiling bounded nothing. The fix for that kept the
     * counter across the marker, which overshot: nothing reset it *ever*, so it became a per-install
     * lifetime budget. Wipes are reachable by ordinary user action — turning off "Require Unlock to
     * Open" with the credential gate on runs a full wipe — so three of those exhausted the budget,
     * and the wipe that actually matters (a thief burning PIN attempts) then got zero retries and
     * abandoned itself on its first failed step.
     *
     * The counter is now scoped to a wipe *episode*: `markWipeInProgress` starts it at 1 when the
     * marker was clear, and increments only when resuming a marker that is already set.
     */
    @Test
    fun wipeAttemptCeiling_climbsWhileResuming_thenResetsForTheNextWipe(): Unit = runBlocking {
        val prefs = context.getSharedPreferences(
            "org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE,
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
                "the count must climb while resuming ONE wipe, then start over for the next one",
                listOf(1, 2, 3, 1, 2),
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
            // Three attempts is the whole budget for one episode: 1, 2, then 3 which gives up.
            // A fourth call would be a NEW episode and would correctly promise a retry again.
            var last: WipeResult? = null
            repeat(3) { last = SecurityWipe.wipeAndResetApp(context) }
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

    /**
     * A wipe that promises a retry must leave the retry something to do.
     *
     * `step("downloadedAttachments")` keeps the URIs it could not delete and throws, producing
     * `Incomplete(willRetry = true)` and the notice "it will be retried when the app next starts".
     * But `step("sharedPrefs")` runs eleven steps later and used to delete the ledger file along
     * with everything else, so the resumed wipe read an empty set, passed the step, and reported
     * **Complete** — telling the user their local data was erased while the attachment plaintext
     * was still sitting in shared Downloads.
     *
     * The undeletable entry is a `content://` URI with an authority no provider claims, so
     * `ContentResolver.delete` throws. That is the same shape as the real case the ledger was
     * hardened for: a MediaStore row this package created and can no longer touch.
     */
    @Test
    fun wipe_keepsTheAttachmentLedgerWhenItsStepFailed(): Unit = runBlocking {
        DownloadedAttachmentLedger.record(
            context,
            android.net.Uri.parse("content://org.kysecurity.mail.no.such.provider/1"),
        )

        val result = SecurityWipe.wipeAndResetApp(context)

        assertTrue(
            "precondition: the attachment step must have failed, got $result",
            result is WipeResult.Incomplete && result.failedSteps.contains("downloadedAttachments"),
        )
        assertTrue(
            "the ledger must survive so the promised retry has work",
            ledgerFile().exists(),
        )
        assertTrue(
            "the undeleted URI must still be recorded",
            context.getSharedPreferences("org.kysecurity.mail.downloaded_attachments", android.content.Context.MODE_PRIVATE)
                .getStringSet("uris", emptySet()).orEmpty().isNotEmpty(),
        )
    }

    /** ...and once the step genuinely succeeds, the ledger goes: retained is not the same as kept
     *  forever, and a stale file would make the next wipe re-try work that is already done. */
    @Test
    fun aSuccessfulAttachmentSweepRemovesTheLedger(): Unit = runBlocking {
        // A media URI for a row that does not exist: the delete affects 0 rows and the re-query
        // finds nothing, so it is correctly treated as already gone.
        DownloadedAttachmentLedger.record(
            context,
            android.net.Uri.parse("content://media/external/downloads/999999999"),
        )
        // record() uses apply(), so the file appears on a background thread. Wait for it rather
        // than racing it — otherwise the assertion below could pass against a file that was never
        // written in the first place.
        assertTrue("precondition: ledger written", awaitLedgerFile())

        DownloadedAttachmentLedger.deleteAll(context)

        assertFalse("a completed sweep must not leave its ledger behind", ledgerFile().exists())
    }

    /**
     * A wipe reached by ten wrong PINs must not leave behind the keys that open this device's
     * envelope. Surviving them would outlive a wipe nobody chose, and the vault key is openable by
     * nothing more than the device unlock.
     *
     * Asserted through the real `wipeAndResetApp`, not the teardown helper, because the ordering is
     * the risk: the sharedPrefs sweep runs after this step and would recreate the vault's file if
     * the step ran too late.
     */
    @Test
    fun wipe_destroysTheDeviceEnrollment(): Unit = runBlocking {
        val vault = org.kysecurity.mail.pgp.EnrollmentVault(context)
        org.kysecurity.mail.pgp.EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))
        assertTrue("precondition: enrollment present", vault.hasBlob())

        SecurityWipe.wipeAndResetApp(context)

        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "agreement key survived the wipe",
            ks.containsAlias(org.kysecurity.mail.pgp.EnrollmentKeyStore.ALIAS),
        )
        assertFalse(
            "vault key survived the wipe",
            ks.containsAlias(org.kysecurity.mail.pgp.EnrollmentVault.ALIAS),
        )
        assertFalse(
            "sealed envelope survived the wipe",
            org.kysecurity.mail.pgp.EnrollmentVault(context).hasBlob(),
        )
    }

    /** The datastore holding the last 30 sender/subject pairs must actually be gone. */
    @Test
    fun wipe_deletesThePushHistoryDatastore(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        repo.appendPayload(
            org.kysecurity.mail.push.PushPayload(
                messageId = "m1", senderName = "Sender X", emailSubject = "Subject Y",
                keywords = listOf("legal"), receivedAtEpochMs = 1L,
            ),
        )
        assertTrue("precondition: push_state written", pushStateFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse("push_state must not survive a wipe", pushStateFile().exists())
    }
}
