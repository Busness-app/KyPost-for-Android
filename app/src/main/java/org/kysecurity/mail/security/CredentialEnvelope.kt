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

/** AndroidKeyStore's OAEP uses MGF1-SHA-1 whatever the transformation name says. */
private val OAEP = OAEPParameterSpec(
    "SHA-256",
    "MGF1",
    MGF1ParameterSpec.SHA1,
    PSource.PSpecified.DEFAULT,
)

object CredentialEnvelope {

    fun encryptCipher(publicKey: PublicKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, publicKey, OAEP) }

    fun decryptCipher(privateKey: PrivateKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, privateKey, OAEP) }

    fun seal(keys: CredentialKeys, cipher: Cipher): ByteArray =
        cipher.doFinal(keys.current.encoded + keys.legacy.encoded)

    fun open(sealed: ByteArray, cipher: Cipher): CredentialKeys? {
        val plaintext = runCatching { cipher.doFinal(sealed) }.getOrNull() ?: return null
        if (plaintext.size != AES_KEY_BYTES * 2) return null
        return CredentialKeys(
            current = SecretKeySpec(plaintext, 0, AES_KEY_BYTES, "AES"),
            legacy = SecretKeySpec(plaintext, AES_KEY_BYTES, AES_KEY_BYTES, "AES"),
        )
    }
}

fun interface BiometricKeySealer {
    fun seal(keys: CredentialKeys)
}
