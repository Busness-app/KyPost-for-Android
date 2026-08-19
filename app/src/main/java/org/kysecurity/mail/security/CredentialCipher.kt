package org.kysecurity.mail.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** One constant for both PIN derivations; 150k, because the Keystore pepper carries the margin. */
internal const val CREDENTIAL_KDF_ITERATIONS = 150_000

private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16
private const val GCM_IV_LENGTH_BYTES = 12
private const val GCM_TAG_LENGTH_BITS = 128

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val PEPPER_KEY_ALIAS = "kypost_credential_pepper"
private const val PIN_PEPPER_KEY_ALIAS = "kypost_pin_pepper"

/** Not a data class: generated equals would be identity over ByteArray. Nothing compares these. */
class WrappedSecret(val iv: ByteArray, val ciphertext: ByteArray)

/** Not a data class, for [WrappedSecret]'s reason: nothing may compare these structurally. */
class CredentialKeys(val current: SecretKeySpec, val legacy: SecretKeySpec) {
    /** Redacted: [SecretKeySpec] has no `toString()` of its own today, so the generated one printed
     *  whatever a future JDK's does. Not a risk worth inheriting. */
    override fun toString(): String = "CredentialKeys(redacted)"
}

/** Injected rather than hardcoded so wrapping stays testable without an AndroidKeyStore. */
fun interface CredentialPepper {
    fun mix(derived: ByteArray): ByteArray
}

/** [mix] reads only and throws if the key is gone; creation is [ensureExists]. */
object KeystoreCredentialPepper : CredentialPepper {
    const val ALIAS = PEPPER_KEY_ALIAS
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(ALIAS) }

    /** Whether it is actually gone. An alias outliving a wipe is a durable, attributable artefact
     *  on a device the user was told is clean — the same reason [KeystoreTripwireKey],
     *  [org.kysecurity.mail.security.AuthGateKey] and [BiometricUnlockVault] all report theirs. */
    fun destroy(): Boolean = deleteKeystoreKey(ALIAS)
}

/** A separate alias from [KeystoreCredentialPepper]'s: verifier and wrapping key must differ. */
object KeystorePinPepper : CredentialPepper {
    const val ALIAS = PIN_PEPPER_KEY_ALIAS
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(ALIAS) }

    /** See [KeystoreCredentialPepper.destroy]. */
    fun destroy(): Boolean = deleteKeystoreKey(ALIAS)
}

/** The alias's mere existence is the tripwire's durable half; a file marker can be forged. */
object KeystoreTripwireKey : CredentialPepper {
    const val ALIAS = "kypost_lock_tripwire"
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(ALIAS) }

    /** @throws PepperUnavailableException when the Keystore itself could not be consulted. */
    fun exists(): Boolean = keystoreKeyExists(ALIAS)
    fun destroy(): Boolean = deleteKeystoreKey(ALIAS)
}

/** As [KeystoreTripwireKey], but for the protection flag: existence is the durable half. */
object KeystoreHlpKey : CredentialPepper {
    const val ALIAS = "kypost_hostile_location"
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(ALIAS) }

    /** @throws PepperUnavailableException when the Keystore itself could not be consulted. */
    fun exists(): Boolean = keystoreKeyExists(ALIAS)
    fun destroy(): Boolean = deleteKeystoreKey(ALIAS)
}

class PepperUnavailableException(alias: String, cause: Throwable? = null) :
    IllegalStateException("Keystore pepper '$alias' is unavailable", cause)

internal fun keystoreHmac(alias: String, derived: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(pepperKey(alias))
    return mac.doFinal(derived)
}

/** Null only on a clean "no entry"; any failure to consult the Keystore throws instead. */
private fun pepperKeyOrNull(alias: String): SecretKey? {
    val entry = runCatching {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.getEntry(alias, null)
    }.getOrElse { throw PepperUnavailableException(alias, it) }
    return (entry as? KeyStore.SecretKeyEntry)?.secretKey
}

/** Reads only; never creates — see [createPepperKeyIfAbsent]. */
private fun pepperKey(alias: String): SecretKey =
    pepperKeyOrNull(alias) ?: throw PepperUnavailableException(alias)

/** Throws when the Keystore is unreadable: generating there would overwrite a good key. */
private fun createPepperKeyIfAbsent(alias: String): SecretKey {
    pepperKeyOrNull(alias)?.let { return it }

    // Deliberately no setUserAuthenticationRequired: background token rotations need this key.
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build())
    return generator.generateKey()
}

/** Removes [alias], returning whether it is actually gone. For [SecurityWipe]'s teardown steps. */
internal fun deleteKeystoreKey(alias: String): Boolean = runCatching {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    keyStore.deleteEntry(alias)
    !keyStore.containsAlias(alias)
}.getOrDefault(false)

/** Whether [alias] currently holds a key. Throws [PepperUnavailableException] if the Keystore
 *  itself could not be consulted, so "gone" is never confused with "unreachable". */
internal fun keystoreKeyExists(alias: String): Boolean = pepperKeyOrNull(alias) != null

/** The Keystore pepper binds the wrapping key to the device; losing it means the user re-pairs. */
object CredentialCipher {
    fun randomSalt(): ByteArray = ByteArray(SALT_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }

    /** Both derivations for [pin]; see [CredentialKeys]. Runs PBKDF2 once and peppers a copy. */
    fun deriveKeys(
        pin: CharArray,
        salt: ByteArray,
        pepper: CredentialPepper = KeystoreCredentialPepper,
    ): CredentialKeys {
        val raw = pbkdf2(pin, salt)
        return CredentialKeys(
            current = SecretKeySpec(pepper.mix(raw), "AES"),
            legacy = SecretKeySpec(raw, "AES"),
        )
    }

    fun wrap(plaintext: String, key: SecretKeySpec): WrappedSecret {
        val iv = ByteArray(GCM_IV_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return WrappedSecret(iv = iv, ciphertext = ciphertext)
    }

    /** Null on a wrong key or a failed GCM tag; callers treat it as unavailable, never a crash. */
    fun unwrap(wrapped: WrappedSecret, key: SecretKeySpec): String? = runCatching {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, wrapped.iv))
        String(cipher.doFinal(wrapped.ciphertext), Charsets.UTF_8)
    }.getOrNull()

    /** See [PinHasher]'s copy: [PBEKeySpec] duplicates the array, and that duplicate is zeroed
     *  here rather than left for the collector. */
    private fun pbkdf2(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, CREDENTIAL_KDF_ITERATIONS, KEY_LENGTH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
