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

/**
 * The Keystore half of biometric unlock.
 *
 * The open path cannot be driven to completion here — the private key needs a live
 * `BiometricPrompt`, which no automated test can satisfy — so the crypto itself is pinned in
 * `CredentialEnvelopeTest` and what this suite proves is everything around it: that the key really
 * does refuse to work without the user, and that a device with no biometric seals nothing rather
 * than sealing under something weaker.
 */
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

    /**
     * The property everything else rests on. A key that could be used without the user would make
     * the sealed blob openable by anyone holding a device image, which is the whole of what the
     * fingerprint is buying.
     */
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

    /**
     * Fail closed on a device with no fingerprint: no key, no blob, and no biometric offer. The
     * unsafe alternative is a key minted under whatever authenticators *are* available, which would
     * quietly turn the device lock-screen PIN into a way past this app's own PIN.
     */
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
