package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

/**
 * Computes an OpenPGP key's fingerprint from the key's own bytes, rather than trusting whatever
 * fingerprint string a server response claims alongside it. A compromised/malicious server (or a
 * MITM on an http fallback) could otherwise send an armored key paired with an unrelated
 * fingerprint string, and the app would have no way to notice the two don't match — the user's
 * out-of-band "does this fingerprint match?" check would be verifying a label with no
 * cryptographic relationship to what actually gets saved. Parsing the key locally and hashing what
 * it actually contains closes that gap.
 */
object PgpFingerprint {

    /** Returns the primary key's fingerprint as space-grouped uppercase hex (comparable to what
     *  `gpg --fingerprint` or any other PGP client shows), or null if [armoredPublicKey] isn't a
     *  parseable OpenPGP public key. Callers must treat null as "reject this key" — never fall back
     *  to displaying a server-supplied fingerprint string instead. */
    fun compute(armoredPublicKey: String): String? = runCatching {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredPublicKey.toByteArray(Charsets.UTF_8)))
        val factory = JcaPGPObjectFactory(decoder)
        val ring = factory.nextObject() as? PGPPublicKeyRing ?: return@runCatching null

        // Verify the whole artifact, not just its first object. Callers persist the ENTIRE armored
        // blob, so anything this function does not look at is key material the user's out-of-band
        // fingerprint check never covered:
        //
        //  - BouncyCastle's PGPPublicKeyRing stream constructor stops its subkey loop at a second
        //    PUBLIC_KEY packet, so an appended second key ring becomes an object nextObject() never
        //    returns — invisible here, still saved and uploaded.
        //  - That same constructor stores subkeys without ever verifying their binding signatures,
        //    so a subkey bound by a foreign signature, or by none at all, survives intact.
        //
        // Both are rejected rather than tolerated: a blob whose fingerprint does not describe all
        // of it cannot be meaningfully confirmed by a human comparing one string.
        if (factory.nextObject() != null) return@runCatching null

        val primary = ring.publicKey
        val subkeysAllBound = ring.publicKeys.asSequence()
            .filter { !it.isMasterKey }
            .all { subkey -> hasValidBindingSignature(primary, subkey) }
        if (!subkeysAllBound) return@runCatching null

        format(primary.fingerprint)
    }.getOrNull()

    private fun hasValidBindingSignature(
        primary: org.bouncycastle.openpgp.PGPPublicKey,
        subkey: org.bouncycastle.openpgp.PGPPublicKey,
    ): Boolean {
        val verifierProvider = org.bouncycastle.openpgp.operator.jcajce
            .JcaPGPContentVerifierBuilderProvider()
        val signatures = subkey.getSignaturesOfType(
            org.bouncycastle.openpgp.PGPSignature.SUBKEY_BINDING,
        )
        while (signatures.hasNext()) {
            val signature = signatures.next()
            val verified = runCatching {
                signature.init(verifierProvider, primary)
                signature.verifyCertification(primary, subkey)
            }.getOrDefault(false)
            if (verified) return true
        }
        return false
    }

    private fun format(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
}
