package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * A stand-in for [KeystoreCredentialPepper] with a fixed key, since a JVM unit test has no
 * AndroidKeyStore. What matters here is that the peppered and unpeppered keys genuinely differ and
 * that a different pepper cannot unwrap — which is the whole point of the mechanism.
 */
private class FixedPepper(private val keyBytes: ByteArray = "test-pepper".toByteArray()) : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA256"))
        return mac.doFinal(derived)
    }
}

class CredentialCipherTest {
    private val pepper = FixedPepper()

    @Test
    fun wrap_thenUnwrap_roundTripsWithCorrectKey() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456", salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, keys.current))
    }

    @Test
    fun unwrap_returnsNull_withWrongPinDerivedKey() {
        val salt = CredentialCipher.randomSalt()
        val correct = CredentialCipher.deriveKeys("123456", salt, pepper)
        val wrong = CredentialCipher.deriveKeys("098231", salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", correct.current)

        assertNull(CredentialCipher.unwrap(wrapped, wrong.current))
    }

    @Test
    fun unwrap_returnsNull_forTamperedCiphertext() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456", salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)
        val tampered = wrapped.copy(ciphertext = wrapped.ciphertext.also { it[0] = it[0].inc() })

        assertNull(CredentialCipher.unwrap(tampered, keys.current))
    }

    @Test
    fun currentKey_differsFromLegacyKey_soAnExtractedBlobIsNotPinOnlyBruteForceable() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456", salt, pepper)

        assertFalse(keys.current.encoded.contentEquals(keys.legacy.encoded))
    }

    @Test
    fun legacyKey_stillUnwrapsSecretsWrappedBeforeThePepperExisted() {
        // The migration path: a v1 blob was wrapped with the bare PBKDF2 output and must stay
        // readable so rewrapPairingIfNeeded can move it onto the peppered key.
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456", salt, pepper)
        val legacyWrapped = CredentialCipher.wrap("legacy-secret", keys.legacy)

        assertEquals("legacy-secret", CredentialCipher.unwrap(legacyWrapped, keys.legacy))
        assertNull(CredentialCipher.unwrap(legacyWrapped, keys.current))
    }

    @Test
    fun differentPepper_cannotUnwrap_evenWithTheCorrectPin() {
        // Stands in for the real property: the pepper key never leaves the device's keystore, so
        // an extracted blob plus a known PIN is not enough to recover the secret off-device.
        val salt = CredentialCipher.randomSalt()
        val onDevice = CredentialCipher.deriveKeys("123456", salt, FixedPepper("device-a".toByteArray()))
        val attacker = CredentialCipher.deriveKeys("123456", salt, FixedPepper("attacker".toByteArray()))
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", onDevice.current)

        assertNull(CredentialCipher.unwrap(wrapped, attacker.current))
        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, onDevice.current))
    }
}
