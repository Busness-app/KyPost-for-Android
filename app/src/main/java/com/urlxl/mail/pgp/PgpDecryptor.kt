package com.urlxl.mail.pgp

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayOutputStream
import java.io.InputStream

/** What the cryptography alone can say about a signature: nothing about *who* the sender is. */
internal data class RawSignature(
    val present: Boolean,
    val valid: Boolean,
    /** The signing key's id, so [SignerBinding] can match it against an address-bound key. */
    val signerKeyId: Long,
)

internal sealed class DecryptResult {
    data class Ok(val plaintext: ByteArray, val signature: RawSignature) : DecryptResult() {
        // Kotlin generates identity equals/hashCode for a ByteArray property, and a data class
        // silently promising structural equality it does not provide is a trap. Nothing compares
        // these, so both are explicitly unsupported rather than subtly wrong.
        override fun equals(other: Any?) = this === other
        override fun hashCode() = System.identityHashCode(this)
    }

    data class Failed(val message: String) : DecryptResult()
}

/**
 * OpenPGP decryption and signature checking, with **no Android imports**.
 *
 * Uses Bouncy Castle's lightweight `Bc*` operators rather than the `Jce*` ones. Android ships a
 * stripped-down "BC" JCE provider that collides with the full one, so the `Jce*` path behaves
 * differently on a device than in a JVM test. The `Bc*` path uses no JCE provider at all, so the
 * same code runs identically in both — which is what makes [PgpDecryptorTest] evidence rather than
 * decoration under the project-wide `isReturnDefaultValues = true`.
 *
 * Every failure is a [DecryptResult.Failed], never a throw: the caller renders an exit-table row.
 */
internal object PgpDecryptor {

    fun decrypt(
        armoredPrivateKey: String,
        armoredMessage: String,
        /** The public keys the address book binds to the displayed sender, from [SignerKey]. A
         *  one-pass signature cannot be completed without one, and the key travelling inside the
         *  signed message is deliberately never used: a message that vouches for itself proves
         *  only that whoever wrote it owned a key. Empty means "present but unverifiable". */
        signerPublicKeys: List<String>,
    ): DecryptResult = runCatching {
        val secretKeys = PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPrivateKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        )

        val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredMessage.byteInputStream(Charsets.UTF_8)),
        )
        var obj = factory.nextObject()
        val encryptedList = (obj as? PGPEncryptedDataList)
            ?: (factory.nextObject() as? PGPEncryptedDataList)
            ?: return DecryptResult.Failed("not an encrypted OpenPGP message")

        // Try every recipient packet: a message may be encrypted to several keys, only one of
        // which is ours, and the packet order is the sender's choice.
        var clear: InputStream? = null
        var encrypted: PGPPublicKeyEncryptedData? = null
        for (item in encryptedList.encryptedDataObjects) {
            val pked = item as? PGPPublicKeyEncryptedData ?: continue
            val secretKey = secretKeys.getSecretKey(pked.keyID) ?: continue
            // Empty passphrase: the armored key came out of the device envelope already
            // unwrapped. A key that still needs one is not a key this device can use.
            val privateKey = secretKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
            )
            clear = pked.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
            encrypted = pked
            break
        }
        if (clear == null || encrypted == null) {
            return DecryptResult.Failed("this message is not encrypted to a key on this device")
        }

        val (plaintext, signature) = readLiteral(clear, signerPublicKeys)

        // Integrity protection is not optional. An unprotected message is malleable, and
        // accepting one would let a tampered ciphertext render as an ordinary message.
        if (encrypted.isIntegrityProtected && !encrypted.verify()) {
            return DecryptResult.Failed("this message failed its integrity check")
        }

        DecryptResult.Ok(plaintext, signature)
    }.getOrElse { DecryptResult.Failed(it.message ?: "could not decrypt this message") }

    /** Verifies an RFC 3156 detached signature over an already-readable body. */
    fun verifyDetached(
        armoredPublicKey: String,
        body: ByteArray,
        armoredSignature: String,
    ): RawSignature = runCatching {
        val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredSignature.byteInputStream(Charsets.UTF_8)),
        )
        val list = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature(present = false, valid = false, signerKeyId = 0L)
        val signature = list[0]

        val rings = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        )
        val key = rings.getPublicKey(signature.keyID)
            ?: return RawSignature(present = true, valid = false, signerKeyId = signature.keyID)

        signature.init(BcPGPContentVerifierBuilderProvider(), key)
        signature.update(body)
        RawSignature(present = true, valid = signature.verify(), signerKeyId = signature.keyID)
    }.getOrElse { RawSignature(present = true, valid = false, signerKeyId = 0L) }

    /**
     * Walks the decrypted stream to its literal data, checking any one-pass signature on the way.
     *
     * The signature is verified over the literal data as it is read, which is why this cannot be
     * split into "get the bytes" and "check the signature" — the one-pass form requires both in a
     * single traversal.
     */
    private fun readLiteral(
        clear: InputStream,
        signerPublicKeys: List<String>,
    ): Pair<ByteArray, RawSignature> {
        var factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(clear)
        var onePass: org.bouncycastle.openpgp.PGPOnePassSignature? = null
        var obj = factory.nextObject()

        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(obj.dataStream)
                }
                is PGPOnePassSignatureList -> {
                    onePass = obj[0]
                }
                is PGPLiteralData -> {
                    val out = ByteArrayOutputStream()
                    obj.inputStream.copyTo(out)
                    val bytes = out.toByteArray()
                    return bytes to verifyOnePass(onePass, bytes, factory, signerPublicKeys)
                }
            }
            obj = factory.nextObject()
        }
        return ByteArray(0) to RawSignature(present = false, valid = false, signerKeyId = 0L)
    }

    /**
     * Completes a one-pass signature against the literal bytes just read.
     *
     * The signer's public key travels inside the signed message often enough to be tempting, and it
     * is deliberately NOT used to self-verify: a message that vouches for itself proves only that
     * whoever wrote it owned a key. Only [signerPublicKeys] — which the address book bound to the
     * displayed sender — can produce `valid = true`.
     *
     * `present = true, valid = false` with no offered key is **not** an accusation. It means "signed,
     * unverifiable here", and [signatureStateFor] is what decides whether that reads as
     * SIGNER_UNKNOWN (no key bound) or INVALID (a key is bound and it did not match).
     */
    private fun verifyOnePass(
        onePass: org.bouncycastle.openpgp.PGPOnePassSignature?,
        body: ByteArray,
        factory: org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory,
        signerPublicKeys: List<String>,
    ): RawSignature {
        if (onePass == null) return RawSignature(present = false, valid = false, signerKeyId = 0L)
        val tail = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature(present = true, valid = false, signerKeyId = onePass.keyID)

        val key = signerPublicKeys.asSequence()
            .mapNotNull { findPublicKey(it, onePass.keyID) }
            .firstOrNull()
            ?: return RawSignature(present = true, valid = false, signerKeyId = onePass.keyID)

        val valid = runCatching {
            onePass.init(BcPGPContentVerifierBuilderProvider(), key)
            onePass.update(body)
            onePass.verify(tail[0])
        }.getOrDefault(false)

        return RawSignature(present = true, valid = valid, signerKeyId = onePass.keyID)
    }

    /**
     * Resolves [keyId] to a public key from an armored blob that may be an ordinary public key
     * ring, or — as in [PgpDecryptorTest], and in principle any caller that already holds the full
     * key pair — a secret key ring. Bouncy Castle's [PGPPublicKeyRingCollection] throws
     * `PGPSecretKeyRing found where PGPPublicKeyRing expected` rather than reading a secret ring's
     * embedded public-key material, so both forms are tried explicitly instead of assuming one
     * parses as the other.
     */
    private fun findPublicKey(
        armored: String,
        keyId: Long,
    ): org.bouncycastle.openpgp.PGPPublicKey? {
        runCatching {
            PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                BcKeyFingerprintCalculator(),
            ).getPublicKey(keyId)
        }.getOrNull()?.let { return it }

        return runCatching {
            PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                BcKeyFingerprintCalculator(),
            ).getSecretKey(keyId)?.publicKey
        }.getOrNull()
    }
}
