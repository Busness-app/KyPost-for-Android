package org.kysecurity.mail.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertFailsWith

/** Stand-in for [KeystoreCredentialPepper]: a JVM unit test has no AndroidKeyStore. */
private class FixedPepper(private val keyBytes: ByteArray = "test-pepper".toByteArray()) : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA256"))
        return mac.doFinal(derived)
    }
}

/** The Keystore refusing to answer — what [PepperUnavailableException] is for. */
private object UnavailablePepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray = throw PepperUnavailableException("test-alias")
}

/** A failure that is NOT the Keystore's, so it must keep propagating. */
private object BrokenPepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray = throw IllegalArgumentException("not a keystore fault")
}

class CredentialCipherTest {
    private val pepper = FixedPepper()

    @Test
    fun wrap_thenUnwrap_roundTripsWithCorrectKey() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)

        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, keys.current))
    }

    @Test
    fun unwrap_returnsNull_withWrongPinDerivedKey() {
        val salt = CredentialCipher.randomSalt()
        val correct = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)
        val wrong = CredentialCipher.deriveKeys("098231".toCharArray(), salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", correct.current)

        assertNull(CredentialCipher.unwrap(wrapped, wrong.current))
    }

    @Test
    fun unwrap_returnsNull_forTamperedCiphertext() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", keys.current)
        val tampered = WrappedSecret(
            iv = wrapped.iv,
            ciphertext = wrapped.ciphertext.copyOf().also { it[0] = it[0].inc() },
        )

        assertNull(CredentialCipher.unwrap(tampered, keys.current))
    }

    @Test
    fun currentKey_differsFromLegacyKey_soAnExtractedBlobIsNotPinOnlyBruteForceable() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)

        assertFalse(keys.current.encoded.contentEquals(keys.legacy.encoded))
    }

    @Test
    fun legacyKey_stillUnwrapsSecretsWrappedBeforeThePepperExisted() {
        val salt = CredentialCipher.randomSalt()
        val keys = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)
        val legacyWrapped = CredentialCipher.wrap("legacy-secret", keys.legacy)

        assertEquals("legacy-secret", CredentialCipher.unwrap(legacyWrapped, keys.legacy))
        assertNull(CredentialCipher.unwrap(legacyWrapped, keys.current))
    }

    @Test
    fun differentPepper_cannotUnwrap_evenWithTheCorrectPin() {
        // Stands in for the real property: the pepper key never leaves the device's keystore, so
        // an extracted blob plus a known PIN is not enough to recover the secret off-device.
        val salt = CredentialCipher.randomSalt()
        val onDevice = CredentialCipher.deriveKeys("123456".toCharArray(), salt, FixedPepper("device-a".toByteArray()))
        val attacker = CredentialCipher.deriveKeys("123456".toCharArray(), salt, FixedPepper("attacker".toByteArray()))
        val wrapped = CredentialCipher.wrap("top-secret-device-secret", onDevice.current)

        assertNull(CredentialCipher.unwrap(wrapped, attacker.current))
        assertEquals("top-secret-device-secret", CredentialCipher.unwrap(wrapped, onDevice.current))
    }

    /** The PIN-change path derives twice and had no handler, so an unreadable Keystore killed the
     *  process in the middle of the staged-write protocol built to survive exactly that. */
    @Test
    fun deriveKeysOrNull_returnsNull_soAPinChangeAbortsInsteadOfCrashing() {
        assertNull(
            CredentialCipher.deriveKeysOrNull("123456".toCharArray(), CredentialCipher.randomSalt(), UnavailablePepper),
        )
    }

    @Test
    fun deriveKeysOrNull_derivesTheSameKeys_asDeriveKeys() {
        val salt = CredentialCipher.randomSalt()
        val expected = CredentialCipher.deriveKeys("123456".toCharArray(), salt, pepper)

        val actual = CredentialCipher.deriveKeysOrNull("123456".toCharArray(), salt, pepper)

        assertNotNull(actual)
        assertArrayEquals(expected.current.encoded, actual!!.current.encoded)
        assertArrayEquals(expected.legacy.encoded, actual.legacy.encoded)
    }

    /** Only the Keystore's own fault is convertible to "abort". Widening this would hide real bugs
     *  behind a message about the Keystore. */
    @Test
    fun deriveKeysOrNull_stillThrows_whenTheFailureIsNotAnUnavailablePepper() {
        assertFailsWith<IllegalArgumentException> {
            CredentialCipher.deriveKeysOrNull("123456".toCharArray(), CredentialCipher.randomSalt(), BrokenPepper)
        }
    }
}
