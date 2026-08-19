package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/** `isReturnDefaultValues = true` is project-wide, so [PgpDecryptor] uses no Android imports. */
class PgpDecryptorTest {

    @Test
    fun plaintextReadStopsAtThePostDecompressionLimit() {
        val read = PgpDecryptor.readAllWithLimit(
            ByteArrayInputStream(ByteArray(MAX_DECRYPTED_PLAINTEXT_BYTES + 1)),
            MAX_DECRYPTED_PLAINTEXT_BYTES,
        )

        assertNull(read)
    }

    @Test
    fun plaintextReadReturnsEveryByteUpToTheLimit() {
        // Chunked accumulation has to reassemble in order and drop nothing — a partial-final-read
        // off-by-one here would silently truncate a decrypted message rather than fail it.
        val source = ByteArray(DEFAULT_BUFFER_SIZE * 2 + 37) { (it % 251).toByte() }

        val read = PgpDecryptor.readAllWithLimit(
            ByteArrayInputStream(source),
            MAX_DECRYPTED_PLAINTEXT_BYTES,
        )

        assertNotNull(read)
        assertTrue(source.contentEquals(read!!))
    }

    @Test
    fun plaintextReadAcceptsExactlyTheLimit() {
        val read = PgpDecryptor.readAllWithLimit(
            ByteArrayInputStream(ByteArray(MAX_DECRYPTED_PLAINTEXT_BYTES)),
            MAX_DECRYPTED_PLAINTEXT_BYTES,
        )

        assertNotNull(read)
        assertEquals(MAX_DECRYPTED_PLAINTEXT_BYTES, read!!.size)
    }

    /** ARMORED_PUBLIC is the same pair's public half — the shape a real caller holds. */
    private val signerKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC)

    @Test
    fun decryptsAMessageEncryptedByGpg() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            TestPgpPrivateKey.ARMORED_MESSAGE,
            signerKeys,
        )

        val ok = result as? DecryptResult.Ok
            ?: throw AssertionError("expected Ok, got $result")
        assertEquals(TestPgpPrivateKey.EXPECTED_PLAINTEXT, String(ok.plaintext, Charsets.UTF_8))
    }

    @Test
    fun reportsTheEmbeddedSignatureAsValid() {
        val ok = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            TestPgpPrivateKey.ARMORED_MESSAGE,
            signerKeys,
        ) as DecryptResult.Ok

        assertTrue("signature should be present", ok.signature.present)
        assertTrue("signature should verify", ok.signature.valid)
    }

    @Test
    fun reportsAPresentSignatureAsUnverifiedWhenNoSignerKeyIsOffered() {
        // Not "no signature": the message IS signed, and we simply cannot check it. The caller
        // maps this through SignerBinding, which turns an unbound signer into SIGNER_UNKNOWN.
        val ok = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(),
            TestPgpPrivateKey.ARMORED_MESSAGE,
            emptyList(),
        ) as DecryptResult.Ok

        assertTrue("signature should still be reported as present", ok.signature.present)
        assertEquals(false, ok.signature.valid)
    }

    @Test
    fun failsClosedOnAMessageThatIsNotOpenPGP() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), "not a pgp message", signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }

    @Test
    fun failsClosedWhenTheKeyCannotDecryptTheMessage() {
        // TestPgpKey is a different, unrelated pair — and a public key at that.
        val result = PgpDecryptor.decrypt(
            TestPgpKey.ARMORED.toCharArray(), TestPgpPrivateKey.ARMORED_MESSAGE, signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }

    @Test
    fun failsClosedOnAnUnprotectedMessage() {
        // A legacy Symmetrically Encrypted Data (tag 9) packet, not the integrity-protected tag 18.
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), TestPgpPrivateKey.ARMORED_UNPROTECTED_MESSAGE, signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }
}
