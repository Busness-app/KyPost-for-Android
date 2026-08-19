package org.kysecurity.mail.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val TAG = "AuthGateKey"

/** Content is irrelevant — only whether the OS lets the key encrypt it at all. */
private val PROOF = ByteArray(16)

/** Device credential is allowed here, unlike the vault: no app PIN exists on this path. */
object AuthGateKey {

    /** Exposed for the wipe assertions; the key itself never leaves this object. */
    const val ALIAS = "kypost_auth_gate"

    /** Null when the device won't hold the key; callers must fail closed. Blocking: Keystore. */
    fun cipher(): Cipher? {
        val existing = runCatching { encryptCipher(ensureKey()) }
        existing.getOrNull()?.let { return it }

        // Nothing is sealed under this key, so a replacement loses nothing.
        Log.e(TAG, "Gate key unusable; minting a replacement", existing.exceptionOrNull())
        return runCatching {
            keyStore().deleteEntry(ALIAS)
            encryptCipher(generate())
        }.onFailure { Log.i(TAG, "This device cannot hold a user-authentication key", it) }
            .getOrNull()
    }

    /** False when the key refuses to run, which is what a forged success callback produces. */
    fun proves(cipher: Cipher): Boolean = runCatching { cipher.doFinal(PROOF) }.isSuccess

    /** Removes the key, naming the step it could not remove so [SecurityWipe] can report an
     *  incomplete wipe rather than a clean one. */
    fun destroy(): List<String> = runCatching {
        val ks = keyStore()
        ks.deleteEntry(ALIAS)
        if (ks.containsAlias(ALIAS)) error("alias survived deleteEntry")
        emptyList<String>()
    }.getOrElse { listOf("deleteAuthGateKey") }

    private fun ensureKey(): SecretKey =
        keyStore().getKey(ALIAS, null) as? SecretKey ?: generate()

    private fun generate(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            // Deliberate: the gate already accepts device credential, so enrollment adds no bypass.
            .setInvalidatedByBiometricEnrollment(false)
            // 0 = per-use auth: the key is unusable except through the CryptoObject a prompt
            // returns, which is exactly the property the gate rests on.
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
    }

    private fun encryptCipher(key: SecretKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
