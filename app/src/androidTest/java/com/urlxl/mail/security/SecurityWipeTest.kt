package com.urlxl.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.urlxl.mail.data.DataRuntime
import com.urlxl.mail.push.PairingData
import com.urlxl.mail.push.PushPayload
import com.urlxl.mail.push.PushRuntime
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
            "com.urlxl.mail.hostile_location_settings",
            "com.urlxl.mail.device_contacts",
            "com.urlxl.mail.keyword_settings",
            "com.urlxl.mail.settings",
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
}
