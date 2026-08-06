package com.urlxl.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.urlxl.mail.pgp.EnrollmentKeyStore
import com.urlxl.mail.pgp.EnrollmentVault
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Leaving an account must destroy that account's sealed envelope.
 *
 * The security wipe and Hostile Location Protection both tear the enrollment down. The account
 * boundary — the one an exported `kypost://native-pair` deep link can drive behind a single
 * confirmation tap — did not, so one account's PGP private key persisted into the next account's
 * session on the same device, under a key that only needs the device lock screen to open.
 */
@RunWith(AndroidJUnit4::class)
class UnpairEnrollmentTeardownTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    @Test
    fun clearingThePairingDestroysTheEnrollment(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        val vault = EnrollmentVault(context)
        EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        repo.clearPairing()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("agreement key survived the unpair", ks.containsAlias(EnrollmentKeyStore.ALIAS))
        assertFalse("vault key survived the unpair", ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse("sealed envelope survived the unpair", EnrollmentVault(context).hasBlob())
    }
}
