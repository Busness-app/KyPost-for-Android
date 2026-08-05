package com.urlxl.mail.pgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_IV = "envelope_iv"
private const val KEY_CT = "envelope_ct"

/**
 * The durable half: an AES-256-GCM Keystore key that requires the device lock screen, and the
 * envelope re-sealed under it.
 *
 * The allowed authenticators include `DEVICE_CREDENTIAL` on purpose, so the key **survives a
 * biometric enrollment change**. Biometric-only would invalidate it whenever a fingerprint is
 * added, costing every ordinary user a full re-enrollment ceremony; and enrolling a biometric
 * already requires the device credential, so the attacker it would exclude already holds what this
 * key accepts. It also keeps `encryptionEnrolled` from flapping false for benign reasons — a marker
 * that cries wolf is one users learn to dismiss.
 *
 * The strict posture is not a switch here. It is Hostile Location Protection, under which there is
 * no envelope at all.
 */
internal class EnrollmentVault(context: Context) {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildPrefs() }

    /** False when the device has no secure lock screen. That is the honest outcome: the envelope's
     *  protection *is* the lock screen, so a device without one cannot hold a meaningful one. */
    fun ensureKey(): Boolean {
        if (runCatching { keyStore().containsAlias(ALIAS) }.getOrDefault(false)) return true
        return generate(strongBox = true) || generate(strongBox = false)
    }

    /**
     * Generates the vault key, and **clears any stored blob in the same breath**.
     *
     * A newly minted key can never open an envelope sealed under a previous one, so retaining the
     * blob across a regeneration is never correct — and it is actively harmful, because
     * [probeEnrollment] establishes only that *a* key exists and that *a* blob exists. `Cipher.init`
     * on GCM touches no ciphertext, so it succeeds against the wrong key, and the probe then reports
     * ENROLLED for a blob nothing in the world can decrypt. The server renders that to the user as
     * "this device can read your encrypted mail", which is the exact lie the marker exists to
     * prevent, and it is the unsafe direction: a user may decommission the device that actually
     * holds a working copy.
     *
     * Reachable whenever the OS destroys the key without any of our code running — the user removing
     * and re-adding the device lock screen is enough.
     */
    private fun generate(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            // 0 = per-use auth, satisfied through a BiometricPrompt.CryptoObject.
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        // Before anything else: a blob sealed under a previous key is unopenable by the key we are
        // about to mint, and keeping it makes probeEnrollment report ENROLLED for a device that can
        // decrypt nothing. Clear it first so an interruption between here and generateKey leaves
        // "no key, no blob" rather than "new key, stale blob".
        prefs.edit().clear().commit()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
        true
    }.getOrElse {
        if (strongBox) Log.i("EnrollmentVault", "StrongBox unavailable, falling back to TEE")
        else Log.e("EnrollmentVault", "Could not generate the vault key", it)
        false
    }

    fun sealCipher(): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secretKey()) }
    }.getOrNull()

    fun openCipher(iv: ByteArray): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv)) }
    }.getOrNull()

    fun store(iv: ByteArray, ciphertext: ByteArray) {
        prefs.edit()
            .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .commit()
    }

    fun stored(): Pair<ByteArray, ByteArray>? {
        val iv = prefs.getString(KEY_IV, null) ?: return null
        val ct = prefs.getString(KEY_CT, null) ?: return null
        return Base64.decode(iv, Base64.NO_WRAP) to Base64.decode(ct, Base64.NO_WRAP)
    }

    fun hasBlob(): Boolean = prefs.contains(KEY_CT)

    /** Its own prefs file, not SecurePairingStore's, so this is a file delete plus one alias
     *  removal — separately assertable, and with no risk of clearing pairing state that Hostile
     *  Location Protection explicitly preserves. */
    fun destroy() {
        runCatching { prefs.edit().clear().commit() }
        runCatching { appContext.deleteSharedPreferences(PREFS_FILE) }
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    internal fun secretKey(): SecretKey = keyStore().getKey(ALIAS, null) as SecretKey

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun buildPrefs(): SharedPreferences {
        val masterKey = MasterKey.Builder(appContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            appContext,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    companion object {
        const val ALIAS = "kypost_device_envelope_seal"
        const val PREFS_FILE = "device_envelope_secure"
    }
}
