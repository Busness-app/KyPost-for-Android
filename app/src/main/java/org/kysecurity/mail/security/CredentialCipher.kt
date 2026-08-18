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

private const val PBKDF2_ITERATIONS = 150_000
private const val KEY_LENGTH_BITS = 256
private const val SALT_LENGTH_BYTES = 16
private const val GCM_IV_LENGTH_BYTES = 12
private const val GCM_TAG_LENGTH_BITS = 128

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val PEPPER_KEY_ALIAS = "kypost_credential_pepper"
private const val PIN_PEPPER_KEY_ALIAS = "kypost_pin_pepper"

/** **Not a `data class`**: Kotlin would generate identity `equals`/`hashCode` over the two
 *  [ByteArray] fields while advertising structural equality, and a wrapped credential is exactly
 *  the kind of value someone reaches for `==` or a `Set` on. Nothing compares these.
 *
 *  The PBKDF2 salt is deliberately not part of this type — it's an input to [CredentialCipher.deriveKeys],
 *  owned and persisted once per pairing by the caller ([org.kysecurity.mail.push.SecurePairingStore]),
 *  not an output of wrapping a single value. */
class WrappedSecret(val iv: ByteArray, val ciphertext: ByteArray)

/**
 * The two keys one PIN can produce, so a secret wrapped under the old scheme is still readable.
 */
data class CredentialKeys(val current: SecretKeySpec, val legacy: SecretKeySpec)

/**
 * Mixes a device-bound secret into the PBKDF2 output. Injected rather than hardcoded so the
 * wrapping logic stays testable off-device — [KeystoreCredentialPepper] needs a real
 * `AndroidKeyStore`, which a JVM unit test does not have.
 */
fun interface CredentialPepper {
    fun mix(derived: ByteArray): ByteArray
}

/**
 * The production pepper: an HMAC-SHA256 key generated in, and never extractable from, the
 * AndroidKeyStore.
 *
 * [mix] reads only, and throws [PepperUnavailableException] if the key is gone. Creation is
 * [ensureExists], called from the paths that are establishing a new secret rather than checking an
 * existing one.
 */
object KeystoreCredentialPepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(PEPPER_KEY_ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(PEPPER_KEY_ALIAS) }
}

/** The app-lock PIN verifier's pepper. A **separate** alias from [KeystoreCredentialPepper]'s so
 *  the verifier and the wrapping key are not interchangeable: with one shared key, a stored PIN
 *  hash and a wrapping key would be the same derivation under two names. */
object KeystorePinPepper : CredentialPepper {
    override fun mix(derived: ByteArray): ByteArray = keystoreHmac(PIN_PEPPER_KEY_ALIAS, derived)
    fun ensureExists() { createPepperKeyIfAbsent(PIN_PEPPER_KEY_ALIAS) }
}

/**
 * The pepper key for [alias] is gone or unusable, so a PIN cannot be evaluated at all.
 */
class PepperUnavailableException(alias: String, cause: Throwable? = null) :
    IllegalStateException("Keystore pepper '$alias' is unavailable", cause)

private fun keystoreHmac(alias: String, derived: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(pepperKey(alias))
    return mac.doFinal(derived)
}

/**
 * Reads the pepper key. **Never creates one** — see [createPepperKeyIfAbsent], which is called only
 * from the paths that are legitimately establishing a new verifier ([PinHasher.hash] via
 * `setPin`, and the first wrap of a device secret).
 *
 * Splitting read from create is the whole fix: on the *verify* path, a missing key means the
 * verifier can no longer be evaluated, and the only safe answer is to say so rather than to mint a
 * new key and start returning "wrong PIN" forever.
 */
private fun pepperKey(alias: String): SecretKey {
    val entry = runCatching {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
    }.getOrElse { throw PepperUnavailableException(alias, it) }
    return entry?.secretKey ?: throw PepperUnavailableException(alias)
}

/** Creates the pepper key if it does not exist yet, and returns it. Idempotent. */
private fun createPepperKeyIfAbsent(alias: String): SecretKey {
    runCatching { return pepperKey(alias) }

    // Deliberately not setUserAuthenticationRequired: the app-lock PIN is this app's own
    // secret, not a device credential the Keystore can gate on, and this key is also needed
    // by background token rotations. Non-exportability is the property being bought here.
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
    generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build())
    return generator.generateKey()
}

/**
 * PIN-derived AES-GCM wrapping for the pairing `deviceSecret`.
 *
 * A 6-digit PIN is a 10^6 keyspace: 150k PBKDF2 iterations alone put a full offline sweep of an
 * extracted blob within minutes on one GPU. [deriveKeys] therefore mixes the PBKDF2 output with a
 * non-exportable AndroidKeyStore HMAC key, so deriving the wrapping key requires the device the
 * secret was wrapped on — an attacker holding only the blob has nothing to brute-force against.
 * The PIN is still required, so the key stays re-derivable on demand after any unlock; what this
 * stops is the attack that never touches the app, and therefore never trips the wipe counter.
 *
 * If the Keystore pepper is lost (OS-level key invalidation, keystore reset), unwrapping fails
 * and the user re-pairs. That is the intended direction to fail in.
 */
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

    /** Null on a wrong key or corrupted/tampered ciphertext (GCM's auth tag fails to verify) —
     *  callers (see [org.kysecurity.mail.push.SecurePairingStore]) treat this as "credential
     *  unavailable right now," never as a crash. */
    fun unwrap(wrapped: WrappedSecret, key: SecretKeySpec): String? = runCatching {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, wrapped.iv))
        String(cipher.doFinal(wrapped.ciphertext), Charsets.UTF_8)
    }.getOrNull()

    /** See [PinHasher]'s copy: [PBEKeySpec] duplicates the array, and that duplicate is zeroed
     *  here rather than left for the collector. */
    private fun pbkdf2(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
