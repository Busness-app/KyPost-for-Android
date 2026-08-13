package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushPayload
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class SecurityWipeTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://example.com",
        registrationUrl = "https://example.com/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    /**
     * The resume-attempt counter is deliberately sticky in production — clearing it along with the
     * in-progress flag is what made MAX_WIPE_RESUMES a rolling window that bounded nothing — so it
     * survives between tests in this class and has to be reset explicitly. Without this, whichever
     * test ran fourth would hit the ceiling and see the marker cleared.
     */
    @org.junit.Before
    fun resetWipeState() {
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun wipeAndResetApp_clearsPinPairingAndLockState() = runBlocking {
        val appLockStore = AppLockStore(context)
        appLockStore.setPin("482913")
        appLockStore.setLockEnabled(true)

        PushRuntime.graph(context).securePairingStore.savePairing(pairing)

        // Room only creates the database file lazily on first access, so force it into existence
        // here — otherwise the post-wipe "file doesn't exist" assertion below would be trivially
        // true even if wipeAndResetApp never deleted anything.
        DataRuntime.graph(context).database.openHelper.writableDatabase
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertTrue(dbFile.exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(AppLockStore(context).isLockEnabled())
        assertFalse(AppLockStore(context).verifyPin("482913"))
        assertNull(PushRuntime.graph(context).securePairingStore.pairing.value)
        assertFalse(dbFile.exists())
    }

    /**
     * The wipe used to stop at the database, the pairing prefs and the app lock — leaving the last
     * 30 push payloads, i.e. sender names and email subjects, sitting in the unencrypted
     * `push_state` DataStore. A wipe that runs *because* the device is presumed hostile cannot
     * leave the message metadata behind.
     */
    @Test
    fun wipeAndResetApp_removesPushHistoryFromDisk() = runBlocking {
        val repository = PushRuntime.graph(context).repository
        repository.savePairing(pairing)
        repository.appendPayload(
            PushPayload(
                messageId = "msg-1",
                senderName = "Confidential Sender",
                emailSubject = "Confidential Subject",
                keywords = listOf("legal"),
                receivedAtEpochMs = 1L,
            ),
        )

        val historyFile = File(context.filesDir, "datastore/push_state.preferences_pb")
        assertTrue("push_state should exist before the wipe", historyFile.exists())
        assertTrue(
            "the subject should be readable on disk before the wipe",
            historyFile.readBytes().toString(Charsets.ISO_8859_1).contains("Confidential Subject"),
        )

        SecurityWipe.wipeAndResetApp(context)

        assertFalse("push_state must not survive a wipe", historyFile.exists())
    }

    @Test
    fun wipeAndResetApp_removesEveryOwnedPreferencesFile() = runBlocking {
        val prefsNames = listOf(
            "org.kysecurity.mail.hostile_location_settings",
            "org.kysecurity.mail.device_contacts",
            "org.kysecurity.mail.keyword_settings",
            "org.kysecurity.mail.settings",
        )
        prefsNames.forEach { name ->
            context.getSharedPreferences(name, android.content.Context.MODE_PRIVATE)
                .edit().putString("marker", "present").commit()
        }

        SecurityWipe.wipeAndResetApp(context)

        prefsNames.forEach { name ->
            assertNull(
                "$name should be gone after a wipe",
                context.getSharedPreferences(name, android.content.Context.MODE_PRIVATE)
                    .getString("marker", null),
            )
        }
    }

    @Test
    fun closeAndDeleteDatabase_leavesTheGraphUsable() = runBlocking {
        // The old contract said callers MUST restart the process afterward or the singleton would
        // keep handing out the closed database. Invalidating the holder makes that a property of
        // the code rather than a doc comment.
        DataRuntime.graph(context).database.openHelper.writableDatabase

        SecurityWipe.closeAndDeleteDatabase(context)

        val rebuilt = DataRuntime.graph(context).database
        assertTrue("DataRuntime should hand out a fresh, open database", rebuilt.openHelper.writableDatabase.isOpen)
    }

    /**
     * The wipe must not claim Complete when a step really failed.
     *
     * `SecurityWipe`'s own KDoc says it "must never report [WipeResult.Complete] unless every step
     * really ran", and three steps could not fail at all: `deviceContacts`, `deregister` and
     * `clearPairingState` each delegated to helpers whose every statement sat in its own
     * `runCatching { }.onFailure { Log }`. The one that mattered most deletes the user's contacts
     * out of the OS provider — outside this app's sandbox — and a failure there was reported as a
     * clean wipe.
     *
     * Provoked through the shared-prefs enumeration, which is the step whose precondition a test
     * can actually remove: with `shared_prefs` made unreadable there is no way to enumerate what
     * needs deleting, and "I cannot see what to delete" must not read as "there was nothing".
     */
    @Test
    fun wipeAndResetApp_reportsIncomplete_whenAStepFails() = runBlocking {
        val sharedPrefsDir = File(context.dataDir, "shared_prefs")
        // Make the directory unlistable. On a device where the test process can't chmod its own
        // data dir this is a no-op and the assertion below would be vacuous, so skip rather than
        // pass for the wrong reason.
        val couldBlock = sharedPrefsDir.exists() && sharedPrefsDir.setReadable(false, false)
        org.junit.Assume.assumeTrue("Could not make shared_prefs unreadable on this device", couldBlock)
        try {
            val result = SecurityWipe.wipeAndResetApp(context)
            assertTrue("Expected Incomplete, got $result", result is WipeResult.Incomplete)
            assertTrue((result as WipeResult.Incomplete).failedSteps.contains("sharedPrefs"))
            // And the marker survives, so the next launch resumes it.
            assertTrue(SecurityWipe.wipeInterrupted(context))
        } finally {
            sharedPrefsDir.setReadable(true, false)
        }
    }

    /**
     * An incomplete wipe must stop resuming eventually.
     *
     * The marker used to be cleared only on a fully clean run, with no ceiling — so a permanently
     * failing step meant the app wiped itself at every launch, forever, with no way for the user to
     * get past it. `clearWebViewState` recursively deleted `cacheDir` in a live process where
     * OkHttp, WebView and ART were still creating files inside it; losing that race is routine.
     *
     * The first fix overcorrected in the other direction: it expressed "stop resuming" by clearing
     * the marker, which threw away the record that data was still on disk. Stopping the retries and
     * forgetting the failure are separate things, and this asserts both halves — no resume, and no
     * forgetting. See [WipeResurrectionTest.pastTheCeiling_theIncompleteStateIsPermanentAndNotForgotten].
     */
    @Test
    fun anIncompleteWipe_stopsResumingAfterTheCeiling_butStaysOnRecord() = runBlocking {
        val sharedPrefsDir = File(context.dataDir, "shared_prefs")
        val couldBlock = sharedPrefsDir.exists() && sharedPrefsDir.setReadable(false, false)
        org.junit.Assume.assumeTrue("Could not make shared_prefs unreadable on this device", couldBlock)
        try {
            var lastResult: WipeResult = WipeResult.Complete
            repeat(6) { lastResult = SecurityWipe.wipeAndResetApp(context) }
            // Still honestly reported as incomplete...
            assertTrue(lastResult is WipeResult.Incomplete)
            // ...no longer scheduled to run again at every launch...
            assertTrue(
                "The app must have stopped resuming the wipe by itself",
                SecurityWipe.abandonedWipe(context) != null,
            )
            // ...and still on record, because the data it could not delete is still here.
            assertTrue(
                "The marker must outlive the retries; clearing it erases the evidence",
                SecurityWipe.wipeInterrupted(context),
            )
        } finally {
            sharedPrefsDir.setReadable(true, false)
        }
    }

    /**
     * Local push teardown must not sit behind the network call.
     *
     * The connector's SQLite database holds the WebPush ECDH private key and auth secret. It used
     * to be deleted *after* the server deregister, inside a `withTimeoutOrNull(3s)` whose bound was
     * set to exactly the deregister client's own 3s `callTimeout` — so the two raced, and an
     * unreachable server (airplane mode: one swipe, before burning ten PINs) reliably cancelled the
     * coroutine before any of it ran. This test has no server at all, which is the failing case.
     */
    @Test
    fun wipeAndResetApp_removesTheUnifiedPushConnectorStore_evenWithNoReachableServer() = runBlocking {
        // Stand in for the connector's own database, which lives in this app's sandbox.
        context.openOrCreateDatabase("unifiedpush-connector", android.content.Context.MODE_PRIVATE, null).use {
            it.execSQL("CREATE TABLE IF NOT EXISTS webpush_keys (secret TEXT)")
            it.execSQL("INSERT INTO webpush_keys VALUES ('ecdh-private-key')")
        }
        assertTrue(context.databaseList().contains("unifiedpush-connector"))

        PushRuntime.graph(context).repository.savePairing(
            pairing.copy(serverUrl = "https://127.0.0.1:1", registrationUrl = "https://127.0.0.1:1/register"),
        )

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(
            "The WebPush ECDH private key survived the wipe",
            context.databaseList().contains("unifiedpush-connector"),
        )
    }

}
