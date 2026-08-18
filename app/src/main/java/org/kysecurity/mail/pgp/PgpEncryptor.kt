package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

internal sealed class EncryptResult {
    data class Ok(val armored: String) : EncryptResult()

    data class Failed(val message: String) : EncryptResult()
}

/**
 * OpenPGP encryption and signing, with **no Android imports** — the outbound mirror of
 * [PgpDecryptor].
 *
 * Uses Bouncy Castle's lightweight `Bc*` operators rather than the `Jce*` ones, for the reason
 * [PgpDecryptor] gives: Android ships a stripped-down "BC" JCE provider that collides with the full
 * one, so the `Jce*` path behaves differently on a device than in a JVM test. The `Bc*` path uses no
 * JCE provider at all, which is what makes [PgpEncryptorTest] evidence rather than decoration under
 * the project-wide `isReturnDefaultValues = true`.
 *
 * Every failure is an [EncryptResult.Failed], never a throw, matching [PgpDecryptor]'s contract.
 */
internal object PgpEncryptor {

    fun encrypt(
        plaintext: ByteArray,
        /** Armored recipient public keys. Empty is refused rather than producing a message nobody
         *  can open. */
        recipientPublicKeys: List<String>,
        /** Armored private key to sign with, or null to encrypt without signing. A [CharArray]
         *  for the same reason [PgpDecryptor.decrypt]'s is. */
        armoredSigningKey: CharArray?,
    ): EncryptResult = runCatching {
        if (plaintext.size > MAX_DECRYPTED_PLAINTEXT_BYTES) {
            return EncryptResult.Failed("this message is too large to encrypt")
        }
        // Explicit rather than emergent. Bouncy Castle already throws when the generator is opened
        // with no recipient method, which runCatching would turn into a Failed — but a documented
        // contract resting on a library's incidental throw is one upgrade away from becoming a
        // message encrypted to nobody and reported as sent.
        if (recipientPublicKeys.isEmpty()) {
            return EncryptResult.Failed("no recipient keys to encrypt to")
        }

        // A recipient whose key cannot be parsed or carries no usable encryption key is a hard
        // failure, never a skip: skipping means that person silently cannot read their own mail
        // while the sender is told the message went out.
        val encryptionKeys = recipientPublicKeys.map { armored ->
            encryptionKeyOf(armored) ?: return EncryptResult.Failed("a recipient key is unusable")
        }

        val generator = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                // Integrity protection is not optional: PgpDecryptor fails closed on a message
                // without it, so omitting it would make our own output unreadable by our own reader.
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom()),
        )
        encryptionKeys.forEach { generator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(it)) }

        val signer = armoredSigningKey?.let {
            signatureGeneratorFor(it) ?: return EncryptResult.Failed("the signing key is unusable")
        }

        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armoredOut ->
            generator.open(armoredOut, ByteArray(BUFFER_BYTES)).use { encryptedOut ->
                val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
                val compressedOut = compressor.open(encryptedOut)

                // Packet order is the whole contract of a one-pass signature, and it is what
                // PgpDecryptor.readLiteral walks: the one-pass header, then the literal data, then
                // the signature. Any other order still decrypts, so only a verified signature
                // proves this is right.
                signer?.generateOnePassVersion(false)?.encode(compressedOut)

                val literalGenerator = PGPLiteralDataGenerator()
                literalGenerator.open(
                    compressedOut,
                    // BINARY, not TEXT: we already emit canonical CRLF ourselves, and TEXT
                    // invites a second round of line-ending canonicalization on the way out.
                    PGPLiteralData.BINARY,
                    "",
                    plaintext.size.toLong(),
                    Date(),
                ).use { literalOut -> literalOut.write(plaintext) }
                signer?.update(plaintext)
                // The literal packet must be closed before the signature packet is written, or the
                // signature lands inside it.
                literalGenerator.close()

                signer?.generate()?.encode(compressedOut)
                compressor.close()
            }
        }
        EncryptResult.Ok(out.toString(Charsets.UTF_8.name()))
    }.getOrElse { EncryptResult.Failed(it.message ?: "could not encrypt this message") }

    /**
     * The armored public half of the enrolled private key, for encrypting the Sent copy.
     *
     * Derived from the unlocked private key and never fetched from the server. A hostile or
     * compromised server that could supply "your" public key would otherwise get every Sent copy
     * encrypted to a key it holds, with nothing on screen looking any different.
     *
     * Carries the whole ring, not just the master key: on the ed25519/cv25519 pairs this product
     * generates only the subkey encrypts, so a master-only export would be unusable as a recipient.
     */
    fun ownPublicKey(armoredPrivateKey: CharArray): String? = runCatching {
        val ring = armoredPrivateKey.useArmoredStream { keyStream ->
            PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), BcKeyFingerprintCalculator())
        }.keyRings.asSequence().firstOrNull() ?: return null

        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armoredOut ->
            PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encode(armoredOut)
        }
        out.toString(Charsets.UTF_8.name())
    }.getOrNull()

    /**
     * The key a message should actually be encrypted to.
     *
     * For the ed25519/cv25519 pairs this product generates the master key signs and only the subkey
     * encrypts, so taking the master would produce a message the recipient cannot open.
     *
     * Recipient key material comes from the relay, which client-side custody exists precisely not to
     * trust, so the blob is validated locally before any of it is used. [PgpFingerprint.compute] is
     * the same validator the QR and contact-sync paths already apply, and it rejects the two shapes
     * that leave the primary fingerprint — the string a user compares out of band — describing only
     * part of what gets used: an appended second key ring, and a subkey bound by a foreign signature
     * or by none at all. Revocation is then filtered here because [PGPPublicKey.isEncryptionKey]
     * ignores it, so a subkey its own owner has retired was otherwise still a valid selection.
     *
     * Returning null is a hard failure at the call site, never a skipped recipient — see [encrypt].
     */
    private fun encryptionKeyOf(armoredPublicKey: String): PGPPublicKey? = runCatching {
        if (PgpFingerprint.compute(armoredPublicKey) == null) return@runCatching null
        PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.asSequence()
            .flatMap { ring -> ring.publicKeys.asSequence() }
            .filter { it.isEncryptionKey && !it.hasRevocation() && !it.hasExpired() }
            .lastOrNull()
    }.getOrNull()

    /**
     * Whether this key's own stated validity period has run out.
     *
     * Checked alongside revocation because [PGPPublicKey.isEncryptionKey] ignores both. Without it,
     * a recipient whose key expired last year still got a message encrypted to it and the sender
     * was told it went out — the failure the "a recipient key is unusable" hard stop in [encrypt]
     * exists to surface, arriving as silence instead.
     *
     * `validSeconds == 0` means "no expiry" in OpenPGP, which is the common case and is not an
     * expiry of zero seconds.
     */
    private fun PGPPublicKey.hasExpired(nowMillis: Long = System.currentTimeMillis()): Boolean {
        val validSeconds = validSeconds
        if (validSeconds <= 0L) return false
        return nowMillis > creationTime.time + validSeconds * 1000L
    }

    /**
     * A one-pass signature generator initialised from the enrolled private key.
     *
     * The empty passphrase matches [PgpDecryptor]: the armored key came out of the device envelope
     * already unwrapped, so a key that still needs one is not a key this device can use.
     */
    private fun signatureGeneratorFor(armoredPrivateKey: CharArray): PGPSignatureGenerator? = runCatching {
        val secretKey = armoredPrivateKey.useArmoredStream { keyStream ->
            PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), BcKeyFingerprintCalculator())
        }.keyRings.asSequence()
            .flatMap { ring -> ring.secretKeys.asSequence() }
            .firstOrNull { it.isSigningKey }
            ?: return null

        val privateKey = secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        PGPSignatureGenerator(
            BcPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256),
            secretKey.publicKey,
        ).apply { init(PGPSignature.BINARY_DOCUMENT, privateKey) }
    }.getOrNull()

    private const val BUFFER_BYTES = 1 shl 16
}
