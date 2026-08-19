package org.kysecurity.mail.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
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

/** One constant for both PIN derivations; 150k, because the Keystore pepper carries the margin.
 *
 *  That "because" is conditional, and [PepperSecurityLevel] is where the condition is checked:
 *  the pepper carries nothing on a device where the Keystore is software-backed. */
internal const val CREDENTIAL_KDF_ITERATIONS = 150_000

private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16
private const val GCM_IV_LENGTH_BYTES = 12
private const val GCM_TAG_LENGTH_BITS = 128

private const val TAG = "CredentialCipher"
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

/** Where a pepper key actually lives.
 *
 *  This is not a diagnostic, it is the load-bearing assumption of the whole PIN threat model.
 *  [PinPolicy] permits an 8-12 digit numeric PIN and [CREDENTIAL_KDF_ITERATIONS] is 150k "because
 *  the Keystore pepper carries the margin" -- and the pepper carries it only while it cannot be
 *  extracted, i.e. only on [TRUSTED_ENVIRONMENT] or [STRONGBOX]. On [SOFTWARE] the pepper is a
 *  file in this app's sandbox, the guessing goes offline, and 10^8 candidates behind 150k rounds
 *  of PBKDF2-HMAC-SHA256 is not a barrier worth the name.
 *
 *  Reported rather than enforced: refusing to run on such a device would lock the user out of
 *  their own mail over a property they cannot change. [SecuritySettingsActivity] renders a warning
 *  callout in the app-lock section when this is not [isHardwareBacked], and
 *  [createPepperKeyIfAbsent] logs it at mint time. */
enum class PepperSecurityLevel {
    STRONGBOX,
    TRUSTED_ENVIRONMENT,

    /** Extractable. The KDF is the only remaining barrier and it was never sized to be one. */
    SOFTWARE,

    /** The Keystore would not say. Treated as [SOFTWARE] by [isHardwareBacked]: an unproven
     *  safety property is not a safety property. */
    UNKNOWN,
}

/** Where the pepper behind [alias] lives, or [PepperSecurityLevel.UNKNOWN] if it cannot be asked.
 *  Queried from the live key rather than recorded at creation, so it cannot go stale. */
fun pepperSecurityLevel(alias: String): PepperSecurityLevel {
    val key = runCatching { pepperKeyOrNull(alias) }.getOrNull() ?: return PepperSecurityLevel.UNKNOWN
    val info = runCatching {
        SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
    }.getOrElse { return PepperSecurityLevel.UNKNOWN }
    return when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> PepperSecurityLevel.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> PepperSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> PepperSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> PepperSecurityLevel.SOFTWARE
        else -> PepperSecurityLevel.UNKNOWN
    }
}

/** UNKNOWN counts as not hardware-backed: never round an unproven property up. */
fun PepperSecurityLevel.isHardwareBacked(): Boolean =
    this == PepperSecurityLevel.STRONGBOX || this == PepperSecurityLevel.TRUSTED_ENVIRONMENT

/** The verifier's pepper is the one the PIN is guessed against; [KeystorePinPepper] is that key. */
fun pinPepperSecurityLevel(): PepperSecurityLevel = pepperSecurityLevel(KeystorePinPepper.ALIAS)

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

/** Throws when the Keystore is unreadable: generating there would overwrite a good key.
 *
 *  StrongBox is requested and then NOT required, because a device without it must still be able
 *  to set a PIN. Which one was granted is read back via [pepperSecurityLevel] rather than
 *  assumed -- see [PepperSecurityLevel] for why that distinction is the whole threat model. */
private fun createPepperKeyIfAbsent(alias: String): SecretKey {
    pepperKeyOrNull(alias)?.let { return it }

    // Deliberately no setUserAuthenticationRequired: background token rotations need this key.
    val key = runCatching { generatePepperKey(alias, strongBox = true) }
        .getOrElse { generatePepperKey(alias, strongBox = false) }
    val level = pepperSecurityLevel(alias)
    if (!level.isHardwareBacked()) {
        // Loud, because this is the one condition under which the PIN's stated cost to guess is
        // not the PIN's real cost to guess. See [PepperSecurityLevel].
        Log.e(TAG, "Pepper '$alias' is $level -- it is extractable, so PIN guessing can go offline")
    }
    return key
}

private fun generatePepperKey(alias: String, strongBox: Boolean): SecretKey {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    generator.init(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build(),
    )
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
        val peppered = pepper.mix(raw)
        try {
            // SecretKeySpec copies, so zeroing both afterwards costs nothing and is the whole
            // point: these are 256 bits of key material each, and the PBEKeySpec below is scrubbed
            // for exactly this reason. Wiping the PIN while leaving the keys DERIVED from it for
            // the collector protects the cheaper of the two secrets.
            return CredentialKeys(
                current = SecretKeySpec(peppered, "AES"),
                legacy = SecretKeySpec(raw, "AES"),
            )
        } finally {
            java.util.Arrays.fill(peppered, 0)
            java.util.Arrays.fill(raw, 0)
        }
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
