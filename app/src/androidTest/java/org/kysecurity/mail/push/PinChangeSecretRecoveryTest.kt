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

/**
 * A PIN change re-wraps the device secret, but the verifier (`app_lock_secure`) and the wrapping
 * (`push_pairing_secure`) are different preference files, so no single `commit()` swaps both.
 * Whichever order they were written in, a process death between them left the secret sealed under
 * a key no surviving PIN derives — and nothing detected it, because `needsCredentialRewrap()` only
 * looks at the scheme version. The relay's eventual 409 read as "re-pair this device", and
 * re-pairing deletes the mailbox.
 *
 * Staging removes the window: for the duration of the change both wrappings are on disk. These
 * tests kill the change at each step and assert the secret is still readable.
 *
 * Instrumented so [CredentialCipher.deriveKeys] uses the real AndroidKeyStore pepper.
 */
@RunWith(AndroidJUnit4::class)
class PinChangeSecretRecoveryTest {
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

    private val salt = CredentialCipher.randomSalt()
    private val oldKeys by lazy { CredentialCipher.deriveKeys("482913".toCharArray(), salt) }
    private val newKeys by lazy { CredentialCipher.deriveKeys("715520".toCharArray(), salt) }

    @Before
    fun clearAnyExistingState() {
        org.kysecurity.mail.security.KeystoreCredentialPepper.ensureExists()
        runBlocking { SecurePairingStore(context).clearPairing() }
    }

    private fun storeWithWrappedSecret(): SecurePairingStore =
        SecurePairingStore(context).also {
            runBlocking { it.savePairing(pairing, gateEnabled = true, credentialKeys = oldKeys, credentialSalt = salt) }
        }

    /** Death after staging, before the verifier swap: the OLD PIN is still authoritative. */
    @Test
    fun interruptedBeforeTheVerifierSwap_theOldPinStillOpensTheSecret() = runBlocking {
        val store = storeWithWrappedSecret()
        store.stagePendingSecret(pairing.deviceSecret!!, newKeys)

        // Crash here. Nothing swapped the PIN, so the old one is what unlocks the app.
        val reopened = SecurePairingStore(context)
        assertEquals(
            "the live wrapping must still open under the PIN that is still authoritative",
            pairing.deviceSecret,
            reopened.pairingSnapshot(oldKeys)?.deviceSecret,
        )
    }

    /** Death after the verifier swap, before the promote: only the NEW PIN exists now. */
    @Test
    fun interruptedAfterTheVerifierSwap_theNewPinOpensTheStagedSecret() = runBlocking {
        val store = storeWithWrappedSecret()
        store.stagePendingSecret(pairing.deviceSecret!!, newKeys)

        // Crash here, after AppLockStore.setPin(newPin) committed in the other file. The live
        // wrapping is now unreadable; the staged one is the copy the new PIN can open.
        val reopened = SecurePairingStore(context)
        assertEquals(
            "the staged wrapping is what makes the new PIN recoverable",
            pairing.deviceSecret,
            reopened.pairingSnapshot(newKeys)?.deviceSecret,
        )
    }

    /** The completed change: promoting clears the staged copy, leaving exactly one wrapping.
     *
     *  The `assertFalse` is the load-bearing one. This test used to assert only that the old PIN
     *  opened nothing — which passed whether or not the staged blob was removed, because staging
     *  writes under the NEW keys and the old PIN could never open it in either case. The staged
     *  copy was in fact never cleared on this path, and the test could not see it. */
    @Test
    fun promotingClearsTheStagedCopy() = runBlocking {
        val store = storeWithWrappedSecret()
        store.stagePendingSecret(pairing.deviceSecret!!, newKeys)
        assertTrue("precondition: the change is mid-flight", store.hasPendingSecret())

        store.savePairing(pairing, gateEnabled = true, credentialKeys = newKeys, credentialSalt = salt)

        val reopened = SecurePairingStore(context)
        assertEquals(pairing.deviceSecret, reopened.pairingSnapshot(newKeys)?.deviceSecret)
        assertFalse(
            "promotion must REMOVE the staged wrapping, not merely stop reading it",
            reopened.hasPendingSecret(),
        )
        // The old PIN must no longer open anything: staging is a transition, not a second key.
        assertNull(
            "a promoted change must not leave the old PIN able to unwrap the secret",
            reopened.pairingSnapshot(oldKeys)?.deviceSecret,
        )
    }

    /** An abandoned change legitimately keeps its staged copy — that IS the recovery path — but
     *  the next successful wrapped write must reclaim it. Without this, a PIN change the user
     *  started and walked away from left the device secret openable under a PIN they never
     *  adopted, on disk, indefinitely. */
    @Test
    fun anAbandonedChangeIsReclaimedByTheNextWrappedWrite() = runBlocking {
        val store = storeWithWrappedSecret()
        store.stagePendingSecret(pairing.deviceSecret!!, newKeys)
        assertTrue("the abandoned staging is what keeps the secret recoverable", store.hasPendingSecret())

        // The user gives up and the app later re-wraps under the PIN that stayed authoritative.
        store.savePairing(pairing, gateEnabled = true, credentialKeys = oldKeys, credentialSalt = salt)

        val reopened = SecurePairingStore(context)
        assertFalse("the never-adopted PIN must not keep a readable copy", reopened.hasPendingSecret())
        assertEquals(pairing.deviceSecret, reopened.pairingSnapshot(oldKeys)?.deviceSecret)
        assertNull(reopened.pairingSnapshot(newKeys)?.deviceSecret)
    }

    /** The state the old code created silently, and which nothing could see. */
    @Test
    fun aStrandedSecretIsDetectable() = runBlocking {
        val store = storeWithWrappedSecret()

        // Wrapped under oldKeys, asked for with newKeys, and no staged copy: unrecoverable.
        assertTrue(
            "a secret no current key can open must be reported, not left to surface as a 409",
            store.deviceSecretIsStranded(newKeys),
        )
        assertFalse("the key that wrapped it is not stranded", store.deviceSecretIsStranded(oldKeys))
        // Locked is not stranded — there is simply no key to try yet.
        assertFalse("no keys means locked, not stranded", store.deviceSecretIsStranded(null))
        // And the scheme-version check genuinely cannot see it, which is why the two are separate.
        assertFalse(
            "needsCredentialRewrap answers a different question and must keep answering it",
            store.needsCredentialRewrap(),
        )
    }

    @Test
    fun clearingThePairingDropsTheStagedCopyToo() = runBlocking {
        val store = storeWithWrappedSecret()
        store.stagePendingSecret(pairing.deviceSecret!!, newKeys)
        store.clearPairing()

        assertNull(SecurePairingStore(context).pairingSnapshot(newKeys))
    }
}
