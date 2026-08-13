package org.kysecurity.mail.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.KeyPairGenerator
import javax.crypto.spec.SecretKeySpec

/**
 * The envelope is exercised here with a plain JCE keypair rather than the AndroidKeyStore one,
 * because the Keystore's private key cannot be used without a live biometric prompt — which no
 * automated test can satisfy. What this suite pins is the part that would silently differ between
 * the two: the OAEP parameters. [CredentialEnvelope] hands the *same* [javax.crypto.Cipher]
 * configuration to both sides, so a round trip that works here works on-device.
 */
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
        assertArrayEquals(keys.current.encoded, opened!!.current.encoded)
        // The legacy key travels too. Dropping it would leave a pre-pepper wrap unreadable after a
        // biometric unlock, so rewrapPairingIfNeeded could never migrate it.
        assertArrayEquals(keys.legacy.encoded, opened.legacy.encoded)
    }

    /** A blob sealed under a key that is now gone reads as "nothing sealed", never as a crash: the
     *  caller's only sane response is to fall back to the PIN, and an exception on the unlock
     *  screen is not that. */
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

    /** Plaintext of the wrong length is a corrupted envelope, not two keys — splitting it anyway
     *  would hand out a short AES key that unwraps nothing and reads as a wrong PIN. */
    @Test
    fun aPlaintextOfTheWrongLengthOpensAsNull() {
        val cipher = CredentialEnvelope.encryptCipher(pair.public)
        val wrongLength = cipher.doFinal(ByteArray(31))

        assertNull(CredentialEnvelope.open(wrongLength, CredentialEnvelope.decryptCipher(pair.private)))
    }
}
