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

    /**
     * Mints a **fresh** keypair for one ceremony, destroying any previous one.
     *
     * - It contradicted the justification for this key carrying no authentication requirement. The
     *   claim is that it "only ever opens the server's transport copy, during a foreground ceremony
     *   with the user present" — but a key that outlives every ceremony is a standing, unauthenticated
     *   path to every envelope the relay has ever retained, which defeats [EnrollmentVault]'s
     *   per-use authentication via a parallel route. An attacker with the relay database and code
     *   execution under this app's UID could open the envelope with no prompt of any kind.
     * - It gave an attacker unbounded lead time to precompute against a known, stable public key,
     *   which is what makes grinding the enrollment code affordable at all.
     *
     * The design already publishes the public half at the start of *every* ceremony rather than once
     * at pairing, so rotating here costs nothing. Call [deleteKeyPair] on both the success and the
     * failure exit of a ceremony so the window is one ceremony, not one install.
     */
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
        // Encoding lives in Sec1Point.kt, pure and Android-free, so both padding branches are
        // unit-testable. A generated-key test here can only ever assert the overall length.
        sec1UncompressedPoint(w.affineX, w.affineY)
    }.getOrNull()

    fun encodedPublicKey(): String? = rawPublicKey()?.let { Base64.getEncoder().encodeToString(it) }

    /**
     * ECDH against the sender's ephemeral public key.
     *
     * **Validates the point before agreeing on it.** `parseDeviceEnvelope` checks that the blob is
     * 65 bytes starting `0x04`, which is a length-and-prefix check and says nothing about whether
     * (x, y) satisfies the curve equation. Feeding an off-curve point to ECDH is the precondition
     * for an invalid-curve attack, which recovers the private key from the residues of repeated
     * agreements — and the only thing standing in the way was whatever `KeyFactory` provider
     * happened to resolve at runtime, on a codebase that elsewhere refuses to depend on exactly
     * that (see [PgpDecryptor]'s note on Android's stripped-down BC provider).
     *
     * Per-ceremony key rotation ([newKeyPair]) already bounds the query budget. This makes the
     * defence something this file states and `EnrollmentKeyStoreTest` can assert, rather than
     * something a dependency might be doing.
     */
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

    /**
     * Whether [point] satisfies `y² = x³ + ax + b (mod p)` and lies in the field.
     *
     * The point at infinity is excluded by construction: it has no affine encoding, so a 65-byte
     * `0x04`-prefixed blob can never represent it. P-256 has prime order, so there is no small
     * subgroup to check for beyond this.
     */
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

    /**
     * Deletes the agreement keypair, reporting whether it is actually gone.
     *
     * The boolean is not decoration: [EnrollmentTeardown] feeds it to a `SecurityWipe.step(...)`,
     * and `step` records a failure only when its body signals one. Swallowing the outcome here —
     * as a bare `runCatching {}` did — would let a surviving key be reported as a completed wipe,
     * the same defect the audit fixed in [EnrollmentVault.destroy].
     */
    fun deleteKeyPair(): Boolean = runCatching {
        val ks = keyStore()
        ks.deleteEntry(ALIAS)
        !ks.containsAlias(ALIAS)
    }.getOrDefault(false)


    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
