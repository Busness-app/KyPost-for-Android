package org.kysecurity.mail.security

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

// Shared with [CredentialCipher] — see [CREDENTIAL_KDF_ITERATIONS] for why it is one constant.
private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16

/** Not a data class: compare only via [PinHasher.matches], which is constant time. */
class PinHash(val salt: ByteArray, val hash: ByteArray)

/** The verifier is Keystore-peppered under its own alias, forcing brute force on-device. */
object PinHasher {
    /** Bumped when the derivation changes, so existing installs can be migrated rather than locked
     *  out. v1 = bare PBKDF2, v2 = PBKDF2 then Keystore-HMAC pepper. */
    const val VERSION_LEGACY_UNPEPPERED = 1
    const val VERSION_PEPPERED = 2

    /** Mints the pepper if missing; [matches] must not, or a correct PIN reads as wrong. */
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

    /** Throws rather than returning false: a false here would count toward the wipe threshold. */
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
        val spec = PBEKeySpec(pin, salt, CREDENTIAL_KDF_ITERATIONS, KEY_LENGTH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
