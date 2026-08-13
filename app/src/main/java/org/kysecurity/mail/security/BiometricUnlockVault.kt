package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val PREFS_FILE = "app_lock_biometric"
private const val KEY_SEALED = "sealed_credential_keys"

/**
 * What a biometric prompt needs to turn a fingerprint into [CredentialKeys]: the cipher to hand to
 * `BiometricPrompt.CryptoObject`, and the blob that cipher will open once the user has authenticated.
 */
class BiometricUnlock(val cipher: Cipher, val sealed: ByteArray)

/**
 * Makes a fingerprint produce the app's real key material instead of setting a boolean.
 *
 * A PIN unlock seals [CredentialKeys] under a Keystore RSA key that requires a strong biometric for
 * every private-key operation; the unlock screen then authenticates with a `CryptoObject` over that
 * key and opens the blob. The difference is not cosmetic: before this, `onAuthenticationSucceeded`
 * flipped a flag, so an instrumented process could unlock the app by hooking one callback without
 * ever producing a secret, and a biometric-only session ran with the credential gate permanently
 * shut.
 *
 * **Biometric only, and invalidated by enrollment.** Including `AUTH_DEVICE_CREDENTIAL` — as
 * [org.kysecurity.mail.pgp.EnrollmentVault] does — would make the device lock-screen PIN a way past
 * this app's own PIN, which it is not today. The cost is that adding a fingerprint destroys the key:
 * biometric unlock then falls back to the PIN until the next PIN unlock re-seals, which is the right
 * direction to fail in, since the attacker that exclusion targets is precisely someone who knows the
 * device credential and enrolls their own finger.
 *
 * The blob is stored in plain `SharedPreferences`. It is already RSA-OAEP ciphertext under a
 * hardware-backed key that will not decrypt without the user, so a second layer of
 * `EncryptedSharedPreferences` would buy nothing and inherit that library's unreadable-keyset
 * failure mode.
 */
class BiometricUnlockVault(context: Context) : BiometricKeySealer {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy {
        appContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    }

    /**
     * Seals [keys] for the next biometric unlock, replacing whatever was there.
     *
     * Re-sealing on every PIN unlock rather than only when nothing is stored: it costs one RSA
     * encryption, and it is what makes recovery from an enrollment-invalidated key automatic — the
     * open path destroys the dead key, and the next PIN unlock mints a new one here with no state to
     * track and no repair path to get wrong.
     *
     * A device with no enrolled biometric cannot hold this key at all, so nothing is stored and any
     * previous blob is dropped. That is not an error: it is the normal state of a PIN-only user.
     */
    override fun seal(keys: CredentialKeys) {
        val publicKey = ensureKey()
        if (publicKey == null) {
            clearBlob()
            return
        }
        runCatching {
            val sealed = CredentialEnvelope.seal(keys, CredentialEnvelope.encryptCipher(publicKey))
            prefs.edit().putString(KEY_SEALED, Base64.encodeToString(sealed, Base64.NO_WRAP)).commit()
        }.onFailure {
            Log.e("BiometricUnlockVault", "Could not seal the credential keys", it)
            clearBlob()
        }
    }

    /**
     * The prompt material, or null when biometric unlock is simply not on offer — nothing sealed, no
     * key, or a key the OS has invalidated because a biometric was enrolled since.
     *
     * Blocking: Keystore and disk. Call it off the main thread.
     *
     * An invalidated key is destroyed here rather than reported. Leaving it would mean every
     * subsequent PIN unlock sealed a fresh blob under a private key that can never open it, and the
     * unlock screen offering a fingerprint that always fails.
     */
    fun prepareUnlock(): BiometricUnlock? {
        val sealed = storedBlob() ?: return null
        val privateKey = runCatching {
            keyStore().getKey(ALIAS, null) as? java.security.PrivateKey
        }.getOrNull() ?: return null

        return try {
            BiometricUnlock(CredentialEnvelope.decryptCipher(privateKey), sealed)
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.i("BiometricUnlockVault", "Biometric enrollment changed; dropping the sealed keys", e)
            destroy()
            null
        } catch (e: Exception) {
            Log.e("BiometricUnlockVault", "Could not prepare a biometric unlock", e)
            null
        }
    }

    /** Removes the key and the sealed blob, naming what it could not remove so
     *  [SecurityWipe] can report an incomplete wipe rather than a clean one. */
    fun destroy(): List<String> {
        val failed = mutableListOf<String>()
        runCatching { prefs.edit().clear().commit() }
            .onFailure { failed += "clearSealedKeys" }
        runCatching {
            val ks = keyStore()
            ks.deleteEntry(ALIAS)
            if (ks.containsAlias(ALIAS)) error("alias survived deleteEntry")
        }.onFailure { failed += "deleteBiometricKey" }
        return failed
    }

    private fun storedBlob(): ByteArray? = runCatching {
        prefs.getString(KEY_SEALED, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
    }.getOrNull()

    private fun clearBlob() {
        runCatching { prefs.edit().remove(KEY_SEALED).commit() }
    }

    /** The public half, generating the pair if it is absent. Null when this device cannot hold the
     *  key — no strong biometric enrolled, or no secure lock screen at all. */
    private fun ensureKey(): java.security.PublicKey? = runCatching {
        val ks = keyStore()
        if (!ks.containsAlias(ALIAS)) generate()
        ks.getCertificate(ALIAS)?.publicKey
    }.getOrElse {
        Log.i("BiometricUnlockVault", "No biometric-bound key on this device", it)
        null
    }

    private fun generate() {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .setUserAuthenticationRequired(true)
            // 0 = per-use auth, satisfied through a BiometricPrompt.CryptoObject.
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        const val ALIAS = "kypost_applock_biometric"
    }
}
