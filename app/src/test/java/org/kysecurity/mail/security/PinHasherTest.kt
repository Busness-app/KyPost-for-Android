package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PinHasherTest {

    /** The production pepper is an AndroidKeyStore HMAC key, which a JVM test has no access to —
     *  same reason [CredentialCipher]'s tests inject one. Any deterministic transform exercises the
     *  peppering path; what matters here is that a pepper participates at all. */
    private val pepper = CredentialPepper { derived -> derived.map { (it + 1).toByte() }.toByteArray() }

    @Test
    fun matches_returnsTrue_forCorrectPin() {
        val salt = PinHasher.randomSalt()
        val hash = PinHasher.hash("12345678", salt, pepper)
        assertTrue(PinHasher.matches("12345678", salt, hash.hash, pepper))
    }

    @Test
    fun matches_returnsFalse_forWrongPin() {
        val salt = PinHasher.randomSalt()
        val hash = PinHasher.hash("12345678", salt, pepper)
        assertFalse(PinHasher.matches("87654321", salt, hash.hash, pepper))
    }

    @Test
    fun hash_isDeterministic_forSameSalt() {
        val salt = PinHasher.randomSalt()
        val first = PinHasher.hash("12345678", salt, pepper)
        val second = PinHasher.hash("12345678", salt, pepper)
        assertTrue(first.hash.contentEquals(second.hash))
    }

    @Test
    fun randomSalt_producesDifferentValues() {
        val a = PinHasher.randomSalt()
        val b = PinHasher.randomSalt()
        assertFalse(a.contentEquals(b))
    }

    /** The peppered verifier must not equal the bare PBKDF2 one, or the pepper is not reaching the
     *  stored value and an extracted hash stays offline-crackable. */
    @Test
    fun pepperedHash_differsFromLegacyHash() {
        val salt = PinHasher.randomSalt()
        val peppered = PinHasher.hash("12345678", salt, pepper)
        val legacy = PinHasher.hashLegacy("12345678", salt)
        assertFalse(peppered.hash.contentEquals(legacy.hash))
    }

    /** A v1 hash written by an older install still has to verify, so the upgrade path in
     *  `AppLockStore.verifyPin` can recognise the correct PIN before rewriting it peppered. */
    @Test
    fun legacyVerifier_stillMatchesLegacyHash() {
        val salt = PinHasher.randomSalt()
        val legacy = PinHasher.hashLegacy("12345678", salt)
        assertTrue(PinHasher.matchesLegacy("12345678", salt, legacy.hash))
        assertFalse(PinHasher.matchesLegacy("87654321", salt, legacy.hash))
    }
}
