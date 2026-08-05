package com.urlxl.mail.pgp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.ECPublicKey
import java.util.Base64
import javax.crypto.KeyAgreement

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

/**
 * This device's enrollment keypair: EC P-256, `PURPOSE_AGREE_KEY`, private half non-extractable.
 *
 * **No user-authentication requirement, deliberately.** This key only ever opens the server's
 * 7-day transport copy of the envelope, during a foreground ceremony with the user present.
 * Gating it would add a prompt that protects nothing durable — the durable protection is
 * [EnrollmentVault]'s re-seal key, which does carry the requirement. Conflating the two would
 * force the weaker requirement onto the key that matters.
 */
internal object EnrollmentKeyStore {

    const val ALIAS = "kypost_device_enrollment_agree"

    fun ensureKeyPair(): Boolean {
        if (keyStore().containsAlias(ALIAS)) return true
        return generate(strongBox = true) || generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
        true
    }.getOrElse {
        // StrongBox is absent on a large share of supported hardware. Falling back to the TEE is
        // the right trade: refusing enrollment there would exclude those users for a marginal gain.
        if (strongBox) Log.i("EnrollmentKeyStore", "StrongBox unavailable, falling back to TEE")
        else Log.e("EnrollmentKeyStore", "Could not generate the enrollment keypair", it)
        false
    }

    /** The uncompressed SEC1 point, `0x04 ‖ X ‖ Y` with each coordinate left-padded to 32 bytes.
     *  Built from [ECPublicKey.getW]; `getEncoded()` would give DER, which is the wrong contract. */
    fun rawPublicKey(): ByteArray? = runCatching {
        val cert = keyStore().getCertificate(ALIAS) ?: return null
        val w = (cert.publicKey as ECPublicKey).w
        // Encoding lives in Sec1Point.kt, pure and Android-free, so both padding branches are
        // unit-testable. A generated-key test here can only ever assert the overall length.
        sec1UncompressedPoint(w.affineX, w.affineY)
    }.getOrNull()

    fun encodedPublicKey(): String? = rawPublicKey()?.let { Base64.getEncoder().encodeToString(it) }

    fun sharedSecret(epk: ByteArray): ByteArray? = runCatching {
        val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val peer = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(
                java.security.spec.ECPoint(
                    BigInteger(1, epk.copyOfRange(1, 33)),
                    BigInteger(1, epk.copyOfRange(33, 65)),
                ),
                (entry.certificate.publicKey as ECPublicKey).params,
            ),
        )
        KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE).run {
            init(entry.privateKey)
            doPhase(peer, true)
            generateSecret()
        }
    }.getOrNull()

    fun deleteKeyPair() {
        runCatching { keyStore().deleteEntry(ALIAS) }
    }


    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
