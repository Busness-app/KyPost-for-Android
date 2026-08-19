package org.kysecurity.mail.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The only place the real KeystoreCredentialPepper device binding is exercised. */
@RunWith(AndroidJUnit4::class)
class CredentialCipherKeystoreTest {

    /** mix only reads the pepper; production creates it on the establish path, so create it here. */
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
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)

        assertFalse(keys.current.encoded.contentEquals(keys.legacy.encoded))
    }

    @Test
    fun roundTripsThroughTheRealKeystorePepper() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, keys.current))
    }

    @Test
    fun theBarePbkdf2KeyCannotOpenAPepperedBlob() {
        // This is the offline-brute-force property: knowing the PIN and the salt is not enough
        // without the on-device pepper.
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("482913".toCharArray(), salt)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertNull(CredentialCipher.unwrap(wrapped, keys.legacy))
    }
}
