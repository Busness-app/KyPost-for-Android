package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * These run on the JVM against a gpg-produced vector. `isReturnDefaultValues = true` is project-wide,
 * so a decryptor that reached for an Android framework class would silently resolve to a stub and
 * these would pass against an implementation that does nothing — which is exactly how
 * `parseDeviceEnvelope` once returned null for every input under three passing tests. Hence
 * [PgpDecryptor] uses Bouncy Castle's lightweight `Bc*` operators and no Android imports at all.
 */
class PgpDecryptorTest {

    /** The signer keys the reader will pass in production: [TestPgpPrivateKey.ARMORED_PUBLIC] is
     *  the same key pair's public half, exported separately by `gpg`, exactly the shape a real
     *  caller holds — [SignerBinding] only ever supplies keys the address book bound to the
     *  displayed sender, never the sender's own message. */
    private val signerKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC)

    @Test
    fun decryptsAMessageEncryptedByGpg() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE,
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
            TestPgpPrivateKey.ARMORED_PRIVATE,
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
            TestPgpPrivateKey.ARMORED_PRIVATE,
            TestPgpPrivateKey.ARMORED_MESSAGE,
            emptyList(),
        ) as DecryptResult.Ok

        assertTrue("signature should still be reported as present", ok.signature.present)
        assertEquals(false, ok.signature.valid)
    }

    @Test
    fun failsClosedOnAMessageThatIsNotOpenPGP() {
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE, "not a pgp message", signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }

    @Test
    fun failsClosedWhenTheKeyCannotDecryptTheMessage() {
        // TestPgpKey is a different, unrelated pair — and a public key at that.
        val result = PgpDecryptor.decrypt(
            TestPgpKey.ARMORED, TestPgpPrivateKey.ARMORED_MESSAGE, signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }

    @Test
    fun failsClosedOnAnUnprotectedMessage() {
        // ARMORED_UNPROTECTED_MESSAGE is a legacy Symmetrically Encrypted Data (tag 9) packet, made
        // with `gpg --rfc2440 --disable-mdc` — not the Sym. Encrypted Integrity Protected Data
        // (tag 18) packet every other fixture here uses. Accepting it would mean a tampered
        // ciphertext could render as an ordinary message: this is the one case the reader can never
        // trust the server not to have produced.
        val result = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE, TestPgpPrivateKey.ARMORED_UNPROTECTED_MESSAGE, signerKeys,
        )

        assertTrue("expected Failed, got $result", result is DecryptResult.Failed)
    }
}
