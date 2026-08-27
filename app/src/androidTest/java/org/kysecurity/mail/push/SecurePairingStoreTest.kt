package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
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

    // Also @After: this class corrupts the store on purpose, and TlsPinNarrowingTest and
    // UnpairEnrollmentTeardownTest open the same file. One failure here used to arrive as twelve.
    @Before
    @After
    fun clearAnyExistingState() {
        context.deleteSharedPreferences("push_pairing_secure")
        runBlocking { SecurePairingStore(context).clearPairing() }
    }

    @Test
    fun savePairing_thenReload_roundTripsAllFields() = runBlocking {
        SecurePairingStore(context).savePairing(pairing, gateEnabled = false)

        // A fresh instance must read the same persisted (decrypted) data back.
        val reloaded = SecurePairingStore(context).pairing.value

        assertEquals(pairing, reloaded)
    }

    @Test
    fun tlsPinCache_tracksEveryWriteAndSurvivesReload() = runBlocking {
        val store = SecurePairingStore(context)
        assertNull(store.currentTlsPin())

        val pin = TlsPin(host = "server.example.com", spkiSha256 = setOf("sha256/AAAA"))
        store.saveTlsPin(pin)
        assertEquals(pin, store.currentTlsPin())
        assertEquals(pin, SecurePairingStore(context).currentTlsPin())

        val rotated = TlsPin(host = "other.example.com", spkiSha256 = setOf("sha256/BBBB"))
        store.saveTlsPin(rotated)
        assertEquals(rotated, store.currentTlsPin())

        store.clearPairing()
        assertNull(store.currentTlsPin())
        assertNull(SecurePairingStore(context).currentTlsPin())
    }

    /** Installs written before chain pinning hold one leaf pin under the old single-String key.
     *  Dropping it on upgrade would read as "pin lost" and refuse every call; carrying it forward
     *  keeps the device connected until the next successful call captures the full chain. */
    @Test
    fun aLegacySingleLeafPinIsCarriedForwardThenReplacedByTheChain() = runBlocking {
        val store = SecurePairingStore(context)
        store.clearPairing()

        // Exactly what an older build left behind: the pre-set keys, written directly.
        openEncryptedPrefsForTest().edit()
            .putString("pair_tls_spki_pin", "sha256/legacy-leaf")
            .putString("pair_tls_spki_pin_host", "server.example.com")
            .commit()

        val migrated = SecurePairingStore(context).currentTlsPin()
        assertEquals(setOf("sha256/legacy-leaf"), migrated?.spkiSha256)
        assertEquals("server.example.com", migrated?.host)

        // The first successful call re-pins the chain, and the legacy key must not outlive it —
        // left behind it would win the fallback read again on the next reload.
        val chain = TlsPin("server.example.com", setOf("sha256/leaf", "sha256/issuer"))
        SecurePairingStore(context).saveTlsPin(chain)
        assertEquals(chain, SecurePairingStore(context).currentTlsPin())
        assertNull(openEncryptedPrefsForTest().getString("pair_tls_spki_pin", null))
    }

    private fun openEncryptedPrefsForTest() =
        org.kysecurity.mail.security.openEncryptedPrefs(context, "push_pairing_secure") {}

    @Test
    fun clearPairing_removesPersistedData() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)
        store.clearPairing()

        assertNull(SecurePairingStore(context).pairing.value)
    }

    /** The reconnect marker, which is what stops a credential-only reset from reading as a fresh
     *  install. `resetPairingCredential` keeps the mail, contacts and keys, so without a record of
     *  whose they are the next pairing skips the account-replacement purge and inherits them. */
    @Test
    fun clearPairing_remembersTheAccountWhoseDataItKept() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)
        assertNull(store.reconnectExpectation())

        store.clearPairing(rememberForReconnect = true)
        val expected = ReconnectExpectation(pairing.subscriberId, pairing.serverUrl)
        assertEquals(expected, store.reconnectExpectation())
        assertEquals(expected, SecurePairingStore(context).reconnectExpectation())

        // A second reconnect has no pairing left to name, and must leave the first marker standing.
        store.clearPairing(rememberForReconnect = true)
        assertEquals(expected, store.reconnectExpectation())

        // Paired again: spent, since the pairing itself now names the account.
        store.savePairing(pairing, gateEnabled = false)
        assertNull(store.reconnectExpectation())

        // And the destructive clear, which purges the data the marker described, drops it outright.
        store.clearPairing(rememberForReconnect = true)
        store.clearPairing()
        assertNull(store.reconnectExpectation())
    }

    @Test
    fun underlyingPrefsFile_doesNotContainPlaintextSecrets() = runBlocking {
        SecurePairingStore(context).savePairing(pairing, gateEnabled = false)

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
        SecurePairingStore(context).savePairing(pairing, gateEnabled = false)

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
        recovered.savePairing(pairing, gateEnabled = false)
        assertEquals(pairing, SecurePairingStore(context).pairing.value)
    }
}
