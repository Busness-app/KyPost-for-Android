package org.kysecurity.mail.security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private const val PBKDF2_ITERATIONS = 150_000
private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16

/**
 * [hash] is never the raw PIN — only this derived, salted value is ever persisted.
 *
 * **Not a `data class`.** Kotlin would generate identity `equals`/`hashCode` for the two
 * [ByteArray] fields while advertising structural equality, and this is a stored PIN verifier: an
 * `==` that silently means "same object" is the worst possible shape for it. Comparison goes
 * through [PinHasher.matches], which uses [java.security.MessageDigest.isEqual] and is constant
 * time; nothing else may compare these.
 */
class PinHash(val salt: ByteArray, val hash: ByteArray)

/**
 * PBKDF2-based PIN hashing for the app-lock PIN (see "Require Unlock to Open" in the
 * 2026-07-22 security-hardening spec). [matches] uses [MessageDigest.isEqual], which is
 * documented as timing-attack-resistant, rather than `ByteArray.contentEquals` — a PIN
 * comparison is exactly the kind of check where short-circuiting on the first differing byte
 * would leak information to a timing attacker.
 *
 * The stored verifier is peppered with a non-exportable Keystore key, for the same reason
 * [CredentialCipher] peppers the wrapping key: PBKDF2 iterations cannot defend a 10^6..10^12
 * keyspace on their own, so an attacker who reads this file must be forced to brute-force *on the
 * device*, through the Keystore, rather than offline on a GPU. Leaving the verifier unpeppered
 * defeated the wrapping key's pepper too — both live in the same sandbox behind the same master
 * key, so whoever can read one can read the other, and recovering the PIN from the cheaper of the
 * two yields the wrapping key as well. A distinct pepper alias from [CredentialCipher]'s keeps the
 * two derivations non-interchangeable.
 */
object PinHasher {
    /** Bumped when the derivation changes, so existing installs can be migrated rather than locked
     *  out. v1 = bare PBKDF2, v2 = PBKDF2 then Keystore-HMAC pepper. */
    const val VERSION_LEGACY_UNPEPPERED = 1
    const val VERSION_PEPPERED = 2

    /**
     * Derives a storable verifier, creating the Keystore pepper if this is the first one.
     *
     * The creation is here and **not** in [matches], because "no pepper key" means opposite things
     * on the two paths: setting a PIN legitimately establishes one, while verifying against a
     * missing one means the stored verifier can no longer be evaluated at all. Minting a key on the
     * verify path made every subsequent correct PIN read as wrong, and ten of those wipe the
     * device. See [PepperUnavailableException].
     */
    fun hash(
        pin: CharArray,
        salt: ByteArray = randomSalt(),
        pepper: CredentialPepper = KeystorePinPepper,
    ): PinHash {
        if (pepper === KeystorePinPepper) KeystorePinPepper.ensureExists()
        return PinHash(salt, derive(pin, salt, pepper))
    }

    /** Read-only derivation: peppers, never creates. Throws [PepperUnavailableException] when the
     *  Keystore key behind [pepper] is gone. */
    private fun derive(pin: CharArray, salt: ByteArray, pepper: CredentialPepper): ByteArray =
        pepper.mix(pbkdf2(pin, salt))

    /** v1 verifier, retained only so a pre-pepper hash can be checked once and upgraded. */
    fun hashLegacy(pin: CharArray, salt: ByteArray): PinHash = PinHash(salt, pbkdf2(pin, salt))

    /**
     * Verifies [pin] against a stored verifier. Never creates a pepper key — see [hash].
     *
     * Throws [PepperUnavailableException] rather than returning false when the pepper is gone: a
     * `false` here is indistinguishable from a wrong PIN, and wrong PINs are counted toward
     * [LockoutPolicy.WIPE_THRESHOLD].
     */
    fun matches(
        pin: CharArray,
        salt: ByteArray,
        expectedHash: ByteArray,
        pepper: CredentialPepper = KeystorePinPepper,
    ): Boolean = MessageDigest.isEqual(derive(pin, salt, pepper), expectedHash)

    fun matchesLegacy(pin: CharArray, salt: ByteArray, expectedHash: ByteArray): Boolean =
        MessageDigest.isEqual(hashLegacy(pin, salt).hash, expectedHash)

    fun randomSalt(): ByteArray = ByteArray(SALT_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }

    /** [PBEKeySpec] copies the array it is given and exposes [PBEKeySpec.clearPassword] to zero
     *  that copy; the PIN reaches here as a [CharArray] precisely so both ends can be wiped. */
    private fun pbkdf2(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
