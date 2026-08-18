package org.kysecurity.mail.pgp

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

/** See [org.kysecurity.mail.MemoryBudget], which holds this alongside the app's other two heap
 *  ceilings — the three interact and were previously set in three files that could not see each
 *  other. */
internal const val MAX_DECRYPTED_PLAINTEXT_BYTES = org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_BYTES

/** How many nested OpenPGP compressed-data packets [PgpDecryptor.readLiteral] will unwrap. Real
 *  messages use one; anything past a handful is a decompression bomb, not a mail. */
internal const val MAX_COMPRESSION_DEPTH = 4

/**
 * What the cryptography alone can say about a signature: nothing about *who* the sender is.
 *
 * **Three states, not two booleans.** This was `(present, valid, signerKeyId)`, which could not
 * express "signed, by a key we were not given" — that case set `valid = false`, making it
 * indistinguishable from a signature that failed to verify. The two mean opposite things to a user:
 * one is "we could not check this", the other is "we checked, and it is wrong", and INVALID is the
 * strongest accusation this app renders.
 *
 * [signatureStateFor] recovered the distinction by re-matching the key id itself, which held only
 * as long as its filter and [PgpDecryptor.verifyOnePass]'s stayed in agreement — and they did not:
 * `signerKeyIdsOf` drops expired and revoked keys, `verifyOnePass` never did, so a signature by an
 * expired subkey verified there as `valid = true` and was then filtered out here. Right answer,
 * wrong reason, one refactor away from being wrong. Naming the state removes the coupling.
 */
internal sealed class RawSignature {
    /** No signature packet at all. */
    object Absent : RawSignature()

    /** Signed, but no key with this id was among the ones offered — so nothing was checked. Never
     *  an accusation; see [PgpSignatureState.SIGNER_UNKNOWN]. */
    data class NoSuchKey(val keyId: Long) : RawSignature()

    /** Signed, a key with this id was found, and [verified] is the result of checking against it. */
    data class Checked(val keyId: Long, val verified: Boolean) : RawSignature()

    val present: Boolean get() = this !is Absent

    /**
     * True only when a key was actually found AND the signature verified against it.
     *
     * Deliberately false for [NoSuchKey]: a caller asking "is this good" must get "no" for a
     * signature nothing checked. A caller that needs to tell the two apart matches on the type.
     */
    val valid: Boolean get() = (this as? Checked)?.verified == true

    /** 0 when there is no signature to attribute. */
    val signerKeyId: Long get() = when (this) {
        is Absent -> 0L
        is NoSuchKey -> keyId
        is Checked -> keyId
    }
}

internal sealed class DecryptResult {
    data class Ok(val plaintext: ByteArray, val signature: RawSignature) : DecryptResult() {
        /** Redacted: the plaintext is a decrypted message. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Ok(redacted)"

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
        /** The enrolled key as a [CharArray], never a `String`: [EnrollmentSession] holds it in a
         *  wipeable array precisely so no caller has to mint an immortal copy to reach this. */
        armoredPrivateKey: CharArray,
        armoredMessage: String,
        /** The public keys the address book binds to the displayed sender, from [SignerKey]. A
         *  one-pass signature cannot be completed without one, and the key travelling inside the
         *  signed message is deliberately never used: a message that vouches for itself proves
         *  only that whoever wrote it owned a key. Empty means "present but unverifiable". */
        signerPublicKeys: List<String>,
    ): DecryptResult = runCatching {
        val secretKeys = armoredPrivateKey.useArmoredStream { keyStream ->
            PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), BcKeyFingerprintCalculator())
        }

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
            // PGPSecretKeyRingCollection has no KeyIdentifier overload, so the id is routed through
            // the non-deprecated accessor; it returns the same long as the deprecated getKeyID().
            val secretKey = secretKeys.getSecretKey(pked.keyIdentifier.keyId) ?: continue
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

        val literal = readLiteral(clear, signerPublicKeys)
            ?: return DecryptResult.Failed("this message is too large or too deeply nested to open")
        val (plaintext, signature) = literal

        // Integrity protection is not optional. An unprotected message is malleable, and
        // accepting one would let a tampered ciphertext render as an ordinary message. The `||`
        // short-circuits before `verify()`, which throws outright on a packet that was never
        // integrity protected in the first place — a legacy Symmetrically Encrypted Data (tag 9)
        // packet rather than the Sym. Encrypted Integrity Protected Data (tag 18) one. Covered by
        // failsClosedOnAnUnprotectedMessage; ARMORED_UNPROTECTED_MESSAGE is the reachable fixture
        // for that branch, made with `gpg --rfc2440 --disable-mdc`.
        if (!encrypted.isIntegrityProtected || !encrypted.verify()) {
            return DecryptResult.Failed("this message failed its integrity check")
        }

        DecryptResult.Ok(plaintext, signature)
    }.getOrElse { DecryptResult.Failed(it.message ?: "could not decrypt this message") }

    /**
     * Verifies an RFC 3156 detached signature over an already-readable body.
     *
     * **The two catches below are scoped separately, and conflating them was a downgrade.** A
     * failure to *parse* means no signature was readable at all, which is `present = false` — the
     * same thing `decrypt()` reports for a message that never parsed as OpenPGP. A failure inside
     * `init`/`update`/`verify` means a signature was found and is broken, which is
     * `present = true, valid = false`.
     *
     * One `runCatching` around the whole body mapped both to `present = false`, so a signature
     * truncated or corrupted in transit rendered as "this message is unsigned" — a state users see
     * on ordinary mail every day — instead of the alarm a mangled signature has to raise.
     */
    fun verifyDetached(
        armoredPublicKey: String,
        body: ByteArray,
        armoredSignature: String,
    ): RawSignature {
        val absent = RawSignature.Absent

        val signature = runCatching {
            val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
                PGPUtil.getDecoderStream(armoredSignature.byteInputStream(Charsets.UTF_8)),
            )
            generateSequence { factory.nextObject() }
                .filterIsInstance<PGPSignatureList>()
                .firstOrNull()
                ?.get(0)
        }.getOrNull() ?: return absent

        // From here on a signature exists, so every remaining failure is INVALID, never ABSENT.
        val key = runCatching {
            PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
                BcKeyFingerprintCalculator(),
            ).getPublicKey(signature.keyID)
        }.getOrNull() ?: return RawSignature.NoSuchKey(signature.keyID)

        val valid = runCatching {
            signature.init(BcPGPContentVerifierBuilderProvider(), key)
            signature.update(body)
            signature.verify()
        }.getOrDefault(false)

        return RawSignature.Checked(signature.keyID, valid)
    }

    /**
     * Walks the decrypted stream to its literal data, checking any one-pass signature on the way.
     */
    private fun readLiteral(
        clear: InputStream,
        signerPublicKeys: List<String>,
    ): Pair<ByteArray, RawSignature>? {
        var factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(clear)
        var onePass: org.bouncycastle.openpgp.PGPOnePassSignature? = null
        var obj = factory.nextObject()
        var depth = 0

        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    // Bounded. `readAllWithLimit` caps the *literal* data; nothing capped how many
                    // compressed layers were unwrapped on the way to it, and each one allocates a
                    // fresh object factory over a fresh inflater. A sender who nests thousands of
                    // compressed packets exhausts the heap before a single literal byte is read —
                    // and the message stays in the mailbox, so it re-fires on every open.
                    if (++depth > MAX_COMPRESSION_DEPTH) return null
                    factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(obj.dataStream)
                }
                is PGPOnePassSignatureList -> {
                    onePass = obj[0]
                }
                is PGPLiteralData -> {
                    val bytes = readAllWithLimit(obj.inputStream, MAX_DECRYPTED_PLAINTEXT_BYTES)
                        ?: return null
                    return bytes to verifyOnePass(onePass, bytes, factory, signerPublicKeys)
                }
            }
            obj = factory.nextObject()
        }
        return ByteArray(0) to RawSignature.Absent
    }

    /**
     * Bounds the stream after OpenPGP decompression, and returns null once [limit] is exceeded.
     *
     * Accumulates fixed chunks and joins once, rather than writing into a [ByteArrayOutputStream]
     * and calling `toByteArray()`. BAOS grows by doubling, so a message at the ceiling held a
     * full-size buffer plus the half-size one it had just outgrown, then allocated a third for the
     * copy — roughly 2.5x peak and ~2x the memcpy, for an input a hostile sender fully controls.
     *
     * **The peak here is 2x [limit], not 1x, and that is irreducible.** Materialising an
     * exact-length [ByteArray] from a stream whose length is unknown until it ends requires the
     * accumulated bytes and the joined result to exist at the same instant, whatever the
     * accumulation strategy. [org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_PEAK_BYTES] states
     * that multiplier rather than leaving the budget to imply 1x; the two must move together.
     *
     * The list is drained as it is joined, so the peak is paid at the first copy and falls away
     * across the rest of it instead of being held until the loop ends.
     *
     * A fresh buffer per `read()` is deliberate and is NOT a hoisting opportunity: a full buffer is
     * handed to [chunks] by reference, so reusing one would mean copying every chunk instead — the
     * same allocation count plus a full extra memcpy of the message. Only the final short read is
     * copied, and only to trim it.
     */
    internal fun readAllWithLimit(input: InputStream, limit: Int): ByteArray? {
        val chunks = ArrayList<ByteArray?>()
        var total = 0
        while (true) {
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            val count = input.read(buffer)
            if (count < 0) break
            if (count > limit - total) return null
            chunks += if (count == buffer.size) buffer else buffer.copyOf(count)
            total += count
        }
        val result = ByteArray(total)
        var offset = 0
        for (index in chunks.indices) {
            val chunk = chunks[index] ?: continue
            chunk.copyInto(result, offset)
            offset += chunk.size
            // Released here rather than when the loop ends: the accumulated bytes and `result`
            // are both live only until the first chunk is copied.
            chunks[index] = null
        }
        return result
    }

    /**
     * Completes a one-pass signature against the literal bytes just read.
     */
    private fun verifyOnePass(
        onePass: org.bouncycastle.openpgp.PGPOnePassSignature?,
        body: ByteArray,
        factory: org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory,
        signerPublicKeys: List<String>,
    ): RawSignature {
        if (onePass == null) return RawSignature.Absent
        val tail = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        val key = signerPublicKeys.asSequence()
            .mapNotNull { armored ->
                runCatching {
                    PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                        BcKeyFingerprintCalculator(),
                    ).getPublicKey(onePass.keyID)
                }.getOrNull()
            }
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        val valid = runCatching {
            onePass.init(BcPGPContentVerifierBuilderProvider(), key)
            onePass.update(body)
            onePass.verify(tail[0])
        }.getOrDefault(false)

        return RawSignature.Checked(onePass.keyID, valid)
    }
}
