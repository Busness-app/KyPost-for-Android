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

/**
 * Turns "the user authenticated" from a callback the app trusts into something the OS attests to,
 * on the one screen that holds no secret of its own to bind a prompt to.
 *
 * [BiometricUnlockVault] is the better shape and is used wherever it can be: there the prompt
 * produces the app's real keys, so a forged success yields nothing usable. It needs the app-lock PIN
 * to have sealed something first. The MFA approval screen must still gate a decision when no PIN is
 * set and nothing is sealed, and the gate below is what stands in: a key that does not exist outside
 * the Keystore, cannot be used without a live authentication, and therefore cannot be produced by an
 * instrumented process hooking `onAuthenticationSucceeded`.
 *
 * **Device credential is allowed here, unlike the unlock vault.** The vault excludes it because the
 * device lock-screen PIN must not become a way past this app's own PIN. There is no app PIN on this
 * path at all, so the screen lock is not bypassing anything — it is the whole of the authentication.
 */
object AuthGateKey {

    /** Exposed for the wipe assertions; the key itself never leaves this object. */
    const val ALIAS = "kypost_auth_gate"

    /**
     * A cipher to hand to `BiometricPrompt.CryptoObject`, or null when this device will not hold the
     * key — on API 31+ that means no secure lock screen at all. Callers must fail closed on null:
     * a prompt raised without one has nothing to prove it ran.
     *
     * Blocking: Keystore. Call it off the main thread.
     */
    fun cipher(): Cipher? {
        val existing = runCatching { encryptCipher(ensureKey()) }
        existing.getOrNull()?.let { return it }

        // A newly enrolled biometric or a changed screen lock kills the key. Nothing is sealed under
        // it, so a fresh one loses nothing and is just as unusable without the user.
        Log.i(TAG, "Gate key unusable; minting a replacement", existing.exceptionOrNull())
        return runCatching {
            keyStore().deleteEntry(ALIAS)
            encryptCipher(generate())
        }.onFailure { Log.i(TAG, "This device cannot hold a user-authentication key", it) }
            .getOrNull()
    }

    /**
     * Whether the OS actually unlocked [cipher] — false when the key refuses to run, which is what
     * a success callback invoked by anything other than a real authentication produces.
     */
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
