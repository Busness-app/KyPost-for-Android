package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.SecureRandom

/**
 * A sender-controlled decompression bomb must be a failed message, not a dead app.
 *
 * `readAllWithLimit` caps the *literal* data at 32 MB. Nothing capped how many nested compressed
 * packets were unwrapped on the way to it, and each layer allocates a fresh object factory over a
 * fresh inflater. Since the message stays in the mailbox, the failure repeats on every open — an
 * unopenable app rather than an unopenable message. Every input here is chosen by whoever sent the
 * mail, which is the entire threat model of a mail client.
 */
class PgpDecompressionBombTest {

    /** Comfortably past [MAX_COMPRESSION_DEPTH], cheap enough to build in a unit test. */
    private val nestingDepth = 64

    @Test
    fun aDeeplyNestedMessageIsRefusedRatherThanUnwrapped() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            nestedMessage(),
            signerPublicKeys = emptyList(),
        )

        assertTrue(
            "expected a Failed result, got ${result::class.simpleName}",
            result is DecryptResult.Failed,
        )
    }

    /** One real message, wrapped in [nestingDepth] compressed-data packets. */
    private fun nestedMessage(): String {
        val recipient = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(TestPgpPrivateKey.ARMORED_PUBLIC.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.asSequence()
            .flatMap { it.publicKeys.asSequence() }
            .first { it.isEncryptionKey }

        val generator = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom()),
        )
        generator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(recipient))

        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armoredOut ->
            generator.open(armoredOut, ByteArray(1 shl 16)).use { encryptedOut ->
                val compressors = ArrayList<PGPCompressedDataGenerator>(nestingDepth)
                var stream: OutputStream = encryptedOut
                repeat(nestingDepth) {
                    val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
                    compressors += compressor
                    stream = compressor.open(stream)
                }
                val literal = PGPLiteralDataGenerator()
                literal.open(stream, PGPLiteralData.BINARY, "", 2L, java.util.Date())
                    .use { it.write("hi".toByteArray(Charsets.UTF_8)) }
                literal.close()
                compressors.asReversed().forEach { it.close() }
            }
        }
        return out.toString(Charsets.UTF_8.name())
    }
}
