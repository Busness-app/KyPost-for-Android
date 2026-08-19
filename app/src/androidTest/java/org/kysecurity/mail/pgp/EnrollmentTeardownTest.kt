package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class EnrollmentTeardownTest {

    @Test
    fun destroysBothKeysAndTheBlob() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val vault = EnrollmentVault(context)
        EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        val failed = EnrollmentTeardown.destroy(context)

        assertEquals("teardown must report nothing left behind", emptyList<String>(), failed)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("agreement key survived", ks.containsAlias(EnrollmentKeyStore.ALIAS))
        assertFalse("vault key survived", ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse("sealed blob survived", EnrollmentVault(context).hasBlob())
    }

    @Test
    fun asecondPassOverNothingReportsSuccess() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        EnrollmentKeyStore.newKeyPair()
        EnrollmentVault(context).ensureKey()

        EnrollmentTeardown.destroy(context)

        assertEquals(emptyList<String>(), EnrollmentTeardown.destroy(context))
    }
}
