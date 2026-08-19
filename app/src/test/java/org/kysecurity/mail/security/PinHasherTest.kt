package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinHasherTest {

    /** The real pepper is a Keystore HMAC key; any deterministic transform exercises the path. */
    private val pepper = CredentialPepper { derived -> derived.map { (it + 1).toByte() }.toByteArray() }

    @Test
    fun matches_returnsTrue_forCorrectPin() {
        val salt = PinHasher.randomSalt()
        val hash = PinHasher.hash("12345678".toCharArray(), salt, pepper)
        assertTrue(PinHasher.matches("12345678".toCharArray(), salt, hash.hash, pepper))
    }

    @Test
    fun matches_returnsFalse_forWrongPin() {
        val salt = PinHasher.randomSalt()
        val hash = PinHasher.hash("12345678".toCharArray(), salt, pepper)
        assertFalse(PinHasher.matches("87654321".toCharArray(), salt, hash.hash, pepper))
    }

    @Test
    fun hash_isDeterministic_forSameSalt() {
        val salt = PinHasher.randomSalt()
        val first = PinHasher.hash("12345678".toCharArray(), salt, pepper)
        val second = PinHasher.hash("12345678".toCharArray(), salt, pepper)
        assertTrue(first.hash.contentEquals(second.hash))
    }

    @Test
    fun randomSalt_producesDifferentValues() {
        val a = PinHasher.randomSalt()
        val b = PinHasher.randomSalt()
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun pepperedHash_differsFromLegacyHash() {
        val salt = PinHasher.randomSalt()
        val peppered = PinHasher.hash("12345678".toCharArray(), salt, pepper)
        val legacy = PinHasher.hashLegacy("12345678".toCharArray(), salt)
        assertFalse(peppered.hash.contentEquals(legacy.hash))
    }

    @Test
    fun legacyVerifier_stillMatchesLegacyHash() {
        val salt = PinHasher.randomSalt()
        val legacy = PinHasher.hashLegacy("12345678".toCharArray(), salt)
        assertTrue(PinHasher.matchesLegacy("12345678".toCharArray(), salt, legacy.hash))
        assertFalse(PinHasher.matchesLegacy("87654321".toCharArray(), salt, legacy.hash))
    }
}
