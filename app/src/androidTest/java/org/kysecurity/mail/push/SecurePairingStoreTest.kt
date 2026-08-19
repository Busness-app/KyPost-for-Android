package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class SecurePairingStoreTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "subscriber-id",
        serverUrl = "https://server.example.com",
        registrationUrl = "https://server.example.com/api/notifications/native/register",
        pairingToken = "top-secret-pairing-token",
        deviceId = "resolved-device-id",
        deviceSecret = "top-secret-device-secret",
        pairedAtEpochMs = 1_000L,
    )

    @Before
    fun clearAnyExistingState() {
        runBlocking { SecurePairingStore(context).clearPairing() }
    }

    @Test
    fun savePairing_thenReload_roundTripsAllFields() = runBlocking {
        SecurePairingStore(context).savePairing(pairing)

        // A fresh instance must read the same persisted (decrypted) data back.
        val reloaded = SecurePairingStore(context).pairing.value

        assertEquals(pairing, reloaded)
    }

    @Test
    fun tlsPinCache_tracksEveryWriteAndSurvivesReload() = runBlocking {
        val store = SecurePairingStore(context)
        assertNull(store.currentTlsPin())

        val pin = TlsPin(host = "server.example.com", spkiSha256 = "sha256/AAAA")
        store.saveTlsPin(pin)
        assertEquals(pin, store.currentTlsPin())
        assertEquals(pin, SecurePairingStore(context).currentTlsPin())

        val rotated = TlsPin(host = "other.example.com", spkiSha256 = "sha256/BBBB")
        store.saveTlsPin(rotated)
        assertEquals(rotated, store.currentTlsPin())

        store.clearPairing()
        assertNull(store.currentTlsPin())
        assertNull(SecurePairingStore(context).currentTlsPin())
    }

    @Test
    fun clearPairing_removesPersistedData() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing)
        store.clearPairing()

        assertNull(SecurePairingStore(context).pairing.value)
    }

    @Test
    fun underlyingPrefsFile_doesNotContainPlaintextSecrets() = runBlocking {
        SecurePairingStore(context).savePairing(pairing)

        val prefsFile = File(context.filesDir.parentFile, "shared_prefs/push_pairing_secure.xml")
        assertTrue("expected encrypted prefs file to exist", prefsFile.exists())

        val rawContents = prefsFile.readText()
        assertFalse(rawContents.contains(pairing.deviceSecret!!))
        assertFalse(rawContents.contains(pairing.pairingToken))
        assertFalse(rawContents.contains(pairing.subscriberId))
    }

    /** A corrupt keyset makes EncryptedSharedPreferences.create throw in init; it must recover. */
    @Test
    fun corruptedKeyset_doesNotCrash_resetsToUnpairedAndStaysUsable() = runBlocking {
        SecurePairingStore(context).savePairing(pairing)

        val rawPrefs = context.getSharedPreferences("push_pairing_secure", android.content.Context.MODE_PRIVATE)
        val valueKeysetKey = "__androidx_security_crypto_encrypted_prefs_value_keyset__"
        val originalKeyset = rawPrefs.getString(valueKeysetKey, null)
        assertTrue("expected an existing value keyset to corrupt", !originalKeyset.isNullOrEmpty())
        val corrupted = originalKeyset!!.toCharArray().also { chars ->
            // Flip a handful of chars mid-string so the keyset is still non-blank but its AEAD
            // ciphertext/tag no longer verifies against the real Keystore key.
            for (i in chars.indices step 7) chars[i] = if (chars[i] == 'A') 'B' else 'A'
        }.concatToString()
        rawPrefs.edit().putString(valueKeysetKey, corrupted).commit()

        // Must not throw despite the corrupted keyset (this line crashed before the fix).
        val recovered = SecurePairingStore(context)

        assertNull("corrupted store should read back as unpaired, not stale/garbage data", recovered.pairing.value)

        // The reset must leave a genuinely working store behind, not just a non-crashing shell.
        recovered.savePairing(pairing)
        assertEquals(pairing, SecurePairingStore(context).pairing.value)
    }
}
