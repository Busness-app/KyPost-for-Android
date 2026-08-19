package org.kysecurity.mail.security

import android.security.keystore.KeyInfo
import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.spec.SecretKeySpec

/** The open path needs a live prompt; the crypto is pinned in CredentialEnvelopeTest. */
@RunWith(AndroidJUnit4::class)
class BiometricUnlockVaultTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val vault = BiometricUnlockVault(context)

    private val keys = CredentialKeys(
        current = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES"),
        legacy = SecretKeySpec(ByteArray(32) { (100 + it).toByte() }, "AES"),
    )

    private fun biometricEnrolled(): Boolean =
        BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    @Before fun clean() { vault.destroy() }
    @After fun cleanup() { vault.destroy() }

    @Test
    fun theSealingKeyRequiresUserAuthentication() {
        assumeTrue("needs an enrolled strong biometric", biometricEnrolled())
        vault.seal(keys)

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = ks.getKey(BiometricUnlockVault.ALIAS, null) as PrivateKey
        val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo

        assertTrue("must require user authentication", info.isUserAuthenticationRequired)
        assertTrue(
            "must die when a biometric is enrolled, so a newly added finger cannot open it",
            info.isInvalidatedByBiometricEnrollment,
        )
    }

    /** Sealing must not itself demand a prompt — it happens as a side effect of a PIN unlock, and a
     *  second unasked-for dialog there is the friction this design avoids. */
    @Test
    fun sealingNeedsNoAuthentication() {
        assumeTrue("needs an enrolled strong biometric", biometricEnrolled())

        vault.seal(keys)

        assertNotNull("a blob must exist after an unattended seal", vault.prepareUnlock())
    }

    /** The other half of the same property: the *private* key refuses without the user. */
    @Test
    fun openingWithoutAuthenticationFails() {
        assumeTrue("needs an enrolled strong biometric", biometricEnrolled())
        vault.seal(keys)
        val unlock = vault.prepareUnlock()!!

        // Cipher.init succeeds on a user-auth key; the refusal lands at doFinal.
        assertThrows(Exception::class.java) { unlock.cipher.doFinal(unlock.sealed) }
    }

    /** Fail closed: a key under whatever authenticators exist would let the device PIN past ours. */
    @Test
    fun withNoEnrolledBiometricNothingIsSealed() {
        assumeTrue("only meaningful without a biometric", !biometricEnrolled())

        vault.seal(keys)

        assertNull(vault.prepareUnlock())
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(BiometricUnlockVault.ALIAS))
    }

    /** Nothing sealed means no biometric offer, whatever the device can do. */
    @Test
    fun prepareUnlockIsNullBeforeAnythingIsSealed() {
        assertNull(vault.prepareUnlock())
    }

    @Test
    fun destroyRemovesBothTheKeyAndTheBlob() {
        vault.seal(keys)

        vault.destroy()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(BiometricUnlockVault.ALIAS))
        assertNull(vault.prepareUnlock())
    }
}
