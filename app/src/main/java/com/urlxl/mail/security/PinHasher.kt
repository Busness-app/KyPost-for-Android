package com.urlxl.mail.security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

private const val PBKDF2_ITERATIONS = 150_000
private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16

/** [hash] is never the raw PIN — only this derived, salted value is ever persisted. */
data class PinHash(val salt: ByteArray, val hash: ByteArray)

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

    fun hash(
        pin: String,
        salt: ByteArray = randomSalt(),
        pepper: CredentialPepper = KeystorePinPepper,
    ): PinHash = PinHash(salt, pepper.mix(pbkdf2(pin, salt)))

    /** v1 verifier, retained only so a pre-pepper hash can be checked once and upgraded. */
    fun hashLegacy(pin: String, salt: ByteArray): PinHash = PinHash(salt, pbkdf2(pin, salt))

    fun matches(
        pin: String,
        salt: ByteArray,
        expectedHash: ByteArray,
        pepper: CredentialPepper = KeystorePinPepper,
    ): Boolean = MessageDigest.isEqual(hash(pin, salt, pepper).hash, expectedHash)

    fun matchesLegacy(pin: String, salt: ByteArray, expectedHash: ByteArray): Boolean =
        MessageDigest.isEqual(hashLegacy(pin, salt).hash, expectedHash)

    fun randomSalt(): ByteArray = ByteArray(SALT_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }

    private fun pbkdf2(pin: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }
}
