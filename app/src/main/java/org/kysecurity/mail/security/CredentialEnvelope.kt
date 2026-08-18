package org.kysecurity.mail.security

import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_BYTES = 32
private const val TRANSFORMATION = "RSA/ECB/OAEPPadding"

/**
 * OAEP with SHA-256 for the digest and **SHA-1 for the MGF1**.
 *
 * That mismatch is not a typo and not a weakness — it is what the AndroidKeyStore provider actually
 * implements. Asking it for `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` gets a cipher whose MGF1 digest
 * is SHA-1 regardless of the name, so sealing with the JCE default (MGF1-SHA-256) and opening on
 * device produces a padding error rather than the keys. Naming both digests explicitly, on both
 * sides, is what makes the round trip in [CredentialEnvelopeTest] evidence about the device.
 */
private val OAEP = OAEPParameterSpec(
    "SHA-256",
    "MGF1",
    MGF1ParameterSpec.SHA1,
    PSource.PSpecified.DEFAULT,
)

/**
 * Seals [CredentialKeys] so a later biometric authentication can produce them again.
 *
 * Deliberately free of any Android dependency, so the parameters above are unit-testable. The
 * Keystore half lives in [BiometricUnlockVault].
 */
object CredentialEnvelope {

    fun encryptCipher(publicKey: PublicKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, publicKey, OAEP) }

    fun decryptCipher(privateKey: PrivateKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, privateKey, OAEP) }

    fun seal(keys: CredentialKeys, cipher: Cipher): ByteArray =
        cipher.doFinal(keys.current.encoded + keys.legacy.encoded)

    /**
     * Null whenever [sealed] does not open into exactly two AES keys — a blob from a key that has
     * since been replaced, a truncated file, anything. Every caller's response is the same and is
     * always safe: fall back to the PIN.
     */
    fun open(sealed: ByteArray, cipher: Cipher): CredentialKeys? {
        val plaintext = runCatching { cipher.doFinal(sealed) }.getOrNull() ?: return null
        if (plaintext.size != AES_KEY_BYTES * 2) return null
        return CredentialKeys(
            current = SecretKeySpec(plaintext, 0, AES_KEY_BYTES, "AES"),
            legacy = SecretKeySpec(plaintext, AES_KEY_BYTES, AES_KEY_BYTES, "AES"),
        )
    }
}

/**
 * Hands [AppLockManager] a way to seal the keys it derives on a PIN unlock without dragging a
 * `Context` — and therefore a real AndroidKeyStore — into a class that is unit-tested on the JVM.
 * [BiometricUnlockVault] is the implementation; the default seals nothing.
 */
fun interface BiometricKeySealer {
    fun seal(keys: CredentialKeys)
}
