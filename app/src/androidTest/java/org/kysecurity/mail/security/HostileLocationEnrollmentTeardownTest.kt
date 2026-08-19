package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.WorkManagerTestInitHelper
import org.kysecurity.mail.pgp.EnrollmentKeyStore
import org.kysecurity.mail.pgp.EnrollmentStateWorker
import org.kysecurity.mail.pgp.EnrollmentVault
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/** HLP destroys the enrollment but must keep the device paired; both are asserted here. */
@RunWith(AndroidJUnit4::class)
class HostileLocationEnrollmentTeardownTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    @Before
    fun initWorkManager() {
        // An executor that never runs anything: this test is about what the toggle enqueues, and
        // letting the worker run would fire a live credentialed call at the fixture's server URL.
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().setExecutor { }.build(),
        )
    }

    @Test
    fun enablingProtectionDestroysEnrollmentButKeepsThePairing(): Unit = runBlocking {
        PushRuntime.graph(context).repository.savePairing(pairing)
        val vault = EnrollmentVault(context)
        EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        // The activity calls this same function. Re-implementing its sequence here would leave a
        // test that stays green while the toggle stops calling it.
        tearDownEnrollmentForHostileLocation(context)

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("agreement key survived", ks.containsAlias(EnrollmentKeyStore.ALIAS))
        assertFalse("vault key survived", ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse("sealed blob survived", EnrollmentVault(context).hasBlob())
        assertNotNull(
            "HLP must not unpair the device",
            PushRuntime.graph(context).securePairingStore.pairingSnapshot(null),
        )
    }

    /** Durable, because the Security page would otherwise show this device as protected until the
     *  next natural registration — and offline is the expected case for this toggle. */
    @Test
    fun enablingProtectionEnqueuesTheStateReport(): Unit = runBlocking {
        PushRuntime.graph(context).repository.savePairing(pairing)

        tearDownEnrollmentForHostileLocation(context)

        val infos = WorkManager.getInstance(context)
            .getWorkInfosForUniqueWork(EnrollmentStateWorker.UNIQUE_NAME).get()
        assertEquals(1, infos.size)
    }
}
