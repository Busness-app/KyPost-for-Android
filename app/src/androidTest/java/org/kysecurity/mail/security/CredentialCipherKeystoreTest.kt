package org.kysecurity.mail.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises the real [KeystoreCredentialPepper] — the unit tests substitute a fixed pepper because
 * a JVM test has no AndroidKeyStore, so this is the only place the actual device binding is
 * verified.
 */
@RunWith(AndroidJUnit4::class)
class CredentialCipherKeystoreTest {

    /**
     * [KeystoreCredentialPepper.mix] reads the pepper and never creates it — the split that stopped
     * a lost verifier key from reading every correct PIN as wrong and wiping the device on the tenth
     * try. Production creates it on the establish path ([AppLockManager.deriveUsingPersistedSalt],
     * [PinHasher.hash]); a test that only ever reads must do the same, or it passes solely on a
     * device where some earlier test happened to establish one.
     */
    @Before
    fun establishThePepper() {
        KeystoreCredentialPepper.ensureExists()
    }

    @Test
    fun keystorePepperIsStableAcrossCalls() {
        // The key is generated once and reused; if it were regenerated per call, every previously
        // wrapped deviceSecret would become permanently unreadable.
        val input = ByteArray(32) { it.toByte() }
        assertEquals(
            KeystoreCredentialPepper.mix(input).toList(),
            KeystoreCredentialPepper.mix(input).toList(),
        )
    }

    @Test
    fun pepperedKeyDiffersFromTheBarePbkdf2Output() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913", salt)

        assertFalse(keys.current.encoded.contentEquals(keys.legacy.encoded))
    }

    @Test
    fun roundTripsThroughTheRealKeystorePepper() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913", salt)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, keys.current))
    }

    @Test
    fun theBarePbkdf2KeyCannotOpenAPepperedBlob() {
        // This is the offline-brute-force property: knowing the PIN and the salt is not enough
        // without the on-device pepper.
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913", salt)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertNull(CredentialCipher.unwrap(wrapped, keys.legacy))
    }
}
