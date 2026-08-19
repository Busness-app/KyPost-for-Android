package org.kysecurity.mail.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.KeyPairGenerator
import javax.crypto.spec.SecretKeySpec

/** Plain JCE keypair: the Keystore key needs a live biometric prompt. Pins the OAEP params. */
class CredentialEnvelopeTest {

    private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private val keys = CredentialKeys(
        current = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES"),
        legacy = SecretKeySpec(ByteArray(32) { (100 + it).toByte() }, "AES"),
    )

    @Test
    fun sealedKeysComeBackIdentical() {
        val sealed = CredentialEnvelope.seal(keys, CredentialEnvelope.encryptCipher(pair.public))

        val opened = CredentialEnvelope.open(sealed, CredentialEnvelope.decryptCipher(pair.private))

        assertNotNull(opened)
        assertArrayEquals(keys.current.encoded, opened!!.keys.current.encoded)
        assertArrayEquals(keys.legacy.encoded, opened.keys.legacy.encoded)
    }

    @Test
    fun aBlobFromADifferentKeyOpensAsNull() {
        val sealed = CredentialEnvelope.seal(keys, CredentialEnvelope.encryptCipher(pair.public))
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        assertNull(CredentialEnvelope.open(sealed, CredentialEnvelope.decryptCipher(other.private)))
    }

    @Test
    fun aTruncatedBlobOpensAsNull() {
        val sealed = CredentialEnvelope.seal(keys, CredentialEnvelope.encryptCipher(pair.public))

        val opened = CredentialEnvelope.open(
            sealed.copyOf(sealed.size - 1),
            CredentialEnvelope.decryptCipher(pair.private),
        )

        assertNull(opened)
    }

    @Test
    fun aPlaintextOfTheWrongLengthOpensAsNull() {
        val cipher = CredentialEnvelope.encryptCipher(pair.public)
        val wrongLength = cipher.doFinal(ByteArray(31))

        assertNull(CredentialEnvelope.open(wrongLength, CredentialEnvelope.decryptCipher(pair.private)))
    }
}
