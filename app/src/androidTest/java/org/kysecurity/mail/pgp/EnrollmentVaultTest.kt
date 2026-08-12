package org.kysecurity.mail.pgp

import android.security.keystore.KeyInfo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

@RunWith(AndroidJUnit4::class)
class EnrollmentVaultTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    // Block body, not an expression body: destroy() returns the steps it could not
    // complete, and JUnit requires @Before/@After to return void.
    @Before fun clean() { vault.destroy() }
    @After fun cleanup() { vault.destroy() }

    /** The property the whole re-seal buys. If this key could be used without the device lock
     *  screen, an extracted device image would open the envelope. */
    @Test
    fun theKeyRequiresUserAuthentication() {
        assertTrue(vault.ensureKey())

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(EnrollmentVault.ALIAS, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo

        assertTrue("key must require user authentication", info.isUserAuthenticationRequired)
    }

    @Test
    fun storesAndReadsBackTheBlob() {
        vault.ensureKey()
        assertFalse(vault.hasBlob())

        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })

        assertTrue(vault.hasBlob())
        val (iv, ct) = vault.stored()!!
        assertNotNull(iv)
        assertTrue(ct.size == 40)
    }

    @Test
    fun destroyRemovesBothTheKeyAndTheBlob() {
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(40))

        vault.destroy()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse(vault.hasBlob())
        assertNull(vault.stored())
    }
}
