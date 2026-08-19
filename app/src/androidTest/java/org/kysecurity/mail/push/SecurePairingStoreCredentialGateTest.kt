package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.security.CredentialCipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Instrumented so [CredentialCipher.deriveKeys] uses the real AndroidKeyStore pepper. */
@RunWith(AndroidJUnit4::class)
class SecurePairingStoreCredentialGateTest {
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
        // deriveKeys only reads the pepper — nothing here would create it, so establish it first.
        org.kysecurity.mail.security.KeystoreCredentialPepper.ensureExists()
        runBlocking { SecurePairingStore(context).clearPairing() }
    }

    @Test
    fun savePairing_withCredentialKeys_readingWithoutKeys_omitsDeviceSecret() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = true, credentialKeys = keys, credentialSalt = salt)

        // A read with no key available (app locked) must come back with deviceSecret == null,
        // not throw and not leak the wrapped ciphertext as if it were the plaintext secret.
        val lockedRead = store.pairingSnapshot(credentialKeys = null)
        assertNull(lockedRead?.deviceSecret)
        assertEquals(pairing.subscriberId, lockedRead?.subscriberId)
    }

    @Test
    fun savePairing_withCredentialKeys_readingWithCorrectKeys_restoresDeviceSecret() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = true, credentialKeys = keys, credentialSalt = salt)

        assertEquals(pairing.deviceSecret, store.pairingSnapshot(credentialKeys = keys)?.deviceSecret)
    }

    @Test
    fun savePairing_withoutCredentialKeys_behavesAsUnwrapped() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)

        assertEquals(pairing.deviceSecret, store.pairingSnapshot(credentialKeys = null)?.deviceSecret)
    }

    @Test
    fun aWrongPinCannotUnwrap() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = true, credentialKeys = CredentialCipher.deriveKeys("482913".toCharArray(), salt), credentialSalt = salt)

        val wrongKeys = CredentialCipher.deriveKeys("000001".toCharArray(), salt)
        assertNull(store.pairingSnapshot(credentialKeys = wrongKeys)?.deviceSecret)
    }

    @Test
    fun needsCredentialRewrap_isTrueWhenStoredUnwrapped_andFalseOnceWrapped() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)
        // This is the state a background FCM token rotation leaves behind in a process that was
        // never PIN-unlocked; rewrapPairingIfNeeded keys off exactly this.
        assertTrue(store.needsCredentialRewrap())

        val salt = CredentialCipher.randomSalt()
        store.savePairing(pairing, gateEnabled = true, credentialKeys = CredentialCipher.deriveKeys("482913".toCharArray(), salt), credentialSalt = salt)
        assertFalse(store.needsCredentialRewrap())
    }

    /** deviceSecret = null used to erase the stored secret, leaving a rotated device with none. */
    @Test
    fun savePairing_withSecretWritePreserve_leavesAWrappedSecretIntact() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = true, credentialKeys = keys, credentialSalt = salt)

        // Exactly what the gate-on/no-key branch does: rewrite the pairing, keep hands off the
        // secret.
        store.savePairing(
            pairing.copy(deviceId = "rotated-device-id", deviceSecret = null),
            SecretWrite.Preserve,
        )

        val reread = store.pairingSnapshot(credentialKeys = keys)
        assertEquals(pairing.deviceSecret, reread?.deviceSecret)
        assertEquals("rotated-device-id", reread?.deviceId)
    }

    @Test
    fun savePairing_withSecretWritePreserve_leavesAnUnwrappedSecretIntact() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)

        store.savePairing(pairing.copy(deviceSecret = null), SecretWrite.Preserve)

        assertEquals(pairing.deviceSecret, store.pairingSnapshot(credentialKeys = null)?.deviceSecret)
    }

    /** The ordinary null still means "there is no secret" — preserving must be opt-in, or
     *  [SecurePairingStore.clearPairing] and a genuinely secret-less pairing would stop working. */
    @Test
    fun savePairing_withoutPreserve_stillClearsTheSecret() = runBlocking {
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = false)

        store.savePairing(pairing.copy(deviceSecret = null), gateEnabled = false)

        assertNull(store.pairingSnapshot(credentialKeys = null)?.deviceSecret)
    }

    @Test
    fun clearPairing_dropsTheWrappedSecretAndTheTlsPin() = runBlocking {
        val salt = CredentialCipher.randomSalt()
        val store = SecurePairingStore(context)
        store.savePairing(pairing, gateEnabled = true, credentialKeys = CredentialCipher.deriveKeys("482913".toCharArray(), salt), credentialSalt = salt)
        store.saveTlsPin(TlsPin(host = "server.example.com", spkiSha256 = setOf("sha256/AAAA")))

        store.clearPairing()

        assertNull(store.pairingSnapshot(credentialKeys = null))
        assertNull(store.currentTlsPin())
    }

    @Test
    fun tlsPin_carriesTheHostItWasObservedOn() = runBlocking {
        val store = SecurePairingStore(context)
        store.saveTlsPin(TlsPin(host = "server.example.com", spkiSha256 = setOf("sha256/AAAA")))

        // Enforcing a pin against a host it did not come from is what bricked requests when the
        // registration URL and the server URL disagreed.
        assertEquals("server.example.com", store.currentTlsPin()?.host)
        assertEquals(setOf("sha256/AAAA"), store.currentTlsPin()?.spkiSha256)
    }
}
