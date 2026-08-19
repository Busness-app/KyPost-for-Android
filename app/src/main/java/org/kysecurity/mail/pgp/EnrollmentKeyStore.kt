package org.kysecurity.mail.pgp

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

/** EC P-256 agreement key. No user-auth requirement, deliberately: its life is one ceremony. */
internal object EnrollmentKeyStore {

    const val ALIAS = "kypost_device_enrollment_agree"

    /** Mints a **fresh** keypair per ceremony: a key that outlives one is an unauthenticated path. */
    fun newKeyPair(): Boolean {
        deleteKeyPair()
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
        sec1UncompressedPoint(w.affineX, w.affineY)
    }.getOrNull()

    fun encodedPublicKey(): String? = rawPublicKey()?.let { Base64.getEncoder().encodeToString(it) }

    /** ECDH against the peer's ephemeral key. Validates it is on-curve first — invalid-curve attack. */
    fun sharedSecret(epk: ByteArray): ByteArray? = runCatching {
        val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val params = (entry.certificate.publicKey as ECPublicKey).params
        // Re-checked here and not only at the parse site: this is a public entry point, and an
        // input contract enforced in a different file is one refactor away from not being enforced.
        if (epk.size != 65 || epk[0] != 0x04.toByte()) return null
        val point = java.security.spec.ECPoint(
            BigInteger(1, epk.copyOfRange(1, 33)),
            BigInteger(1, epk.copyOfRange(33, 65)),
        )
        if (!isOnCurve(point, params)) {
            Log.e("EnrollmentKeyStore", "Rejecting an ephemeral public key that is not on the curve")
            return null
        }
        val peer = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.ECPublicKeySpec(point, params))
        KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE).run {
            init(entry.privateKey)
            doPhase(peer, true)
            generateSecret()
        }
    }.getOrNull()

    /** y^2 = x^3 + ax + b (mod p) and in-field. P-256 has prime order, so no subgroup check. */
    internal fun isOnCurve(point: java.security.spec.ECPoint, params: java.security.spec.ECParameterSpec): Boolean {
        val curve = params.curve
        val p = (curve.field as? java.security.spec.ECFieldFp)?.p ?: return false
        val x = point.affineX
        val y = point.affineY
        if (x.signum() < 0 || x >= p || y.signum() < 0 || y >= p) return false
        val lhs = y.modPow(BigInteger.valueOf(2), p)
        val rhs = (x.modPow(BigInteger.valueOf(3), p) + curve.a.multiply(x) + curve.b).mod(p)
        return lhs == rhs
    }

    /** Reports whether the key is really gone: [EnrollmentTeardown] feeds it to `SecurityWipe`. */
    fun deleteKeyPair(): Boolean = runCatching {
        val ks = keyStore()
        ks.deleteEntry(ALIAS)
        !ks.containsAlias(ALIAS)
    }.getOrDefault(false)


    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
