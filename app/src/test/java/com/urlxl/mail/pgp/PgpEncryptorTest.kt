package com.urlxl.mail.pgp

import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [PgpDecryptor] is the oracle for every test here.
 *
 * A round trip through the app's own decrypt path is what makes these tests evidence rather than
 * self-agreement: the ciphertext has to satisfy the same packet walk, the same integrity check and
 * the same one-pass signature completion that a real inbound message does. A fixture generated and
 * checked by the code under test alone would prove only that the encoder agrees with itself.
 */
class PgpEncryptorTest {

    @Test
    fun encryptedMessageRoundTripsThroughPgpDecryptor() {
        val plaintext = "Hello from an on-device encrypted send.\n".toByteArray(Charsets.UTF_8)

        val result = PgpEncryptor.encrypt(
            plaintext = plaintext,
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = null,
        )

        val armored = (result as EncryptResult.Ok).armored
        assertTrue(
            "output must be ASCII-armored so it can sit in a PGP/MIME part",
            armored.startsWith("-----BEGIN PGP MESSAGE-----"),
        )

        val decrypted = PgpDecryptor.decrypt(
            armoredPrivateKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            armoredMessage = armored,
            signerPublicKeys = emptyList(),
        )
        assertEquals(
            String(plaintext, Charsets.UTF_8),
            String((decrypted as DecryptResult.Ok).plaintext, Charsets.UTF_8),
        )
    }

    /**
     * The signature must complete through the one-pass path [PgpDecryptor.readLiteral] walks, which
     * requires the one-pass packet to precede the literal data and the signature packet to follow
     * it. Producing the packets in any other order still yields a message that decrypts, so only a
     * verified signature proves the nesting is right.
     */
    @Test
    fun signedMessageVerifiesAgainstTheSignersPublicKey() {
        val plaintext = "Signed and encrypted on the device.\n".toByteArray(Charsets.UTF_8)

        val result = PgpEncryptor.encrypt(
            plaintext = plaintext,
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = TestPgpPrivateKey.ARMORED_PRIVATE,
        )

        val decrypted = PgpDecryptor.decrypt(
            armoredPrivateKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            armoredMessage = (result as EncryptResult.Ok).armored,
            signerPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertEquals(String(plaintext, Charsets.UTF_8), String(decrypted.plaintext, Charsets.UTF_8))
        assertTrue("a signed message must report a signature", decrypted.signature.present)
        assertTrue("the signature must verify against the signer's key", decrypted.signature.valid)
    }

    @Test
    fun unsignedMessageReportsNoSignature() {
        val result = PgpEncryptor.encrypt(
            plaintext = "No signature here.\n".toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = null,
        )

        val decrypted = PgpDecryptor.decrypt(
            armoredPrivateKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            armoredMessage = (result as EncryptResult.Ok).armored,
            signerPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok

        assertFalse(
            "an unsigned message must not claim a signature — a false 'signed' badge is worse than none",
            decrypted.signature.present,
        )
    }

    /** Encrypting to nobody would produce a message no one — not even the sender — can open, and
     *  returning it as success would send it. */
    @Test
    fun refusesAnEmptyRecipientList() {
        val result = PgpEncryptor.encrypt(
            plaintext = "Nobody to read this.\n".toByteArray(Charsets.UTF_8),
            recipientPublicKeys = emptyList(),
            armoredSigningKey = null,
        )

        assertTrue("an empty recipient list must fail, not encrypt to nobody", result is EncryptResult.Failed)
    }

    /**
     * A recipient whose key will not parse must fail the whole send, never be quietly dropped.
     *
     * Skipping is the dangerous behaviour: the message goes out, the UI reports success, and that
     * person silently receives mail they cannot read — or, on the delivery split, receives nothing
     * at all while the sender believes otherwise.
     */
    @Test
    fun failsRatherThanSkippingAnUnusableRecipientKey() {
        val result = PgpEncryptor.encrypt(
            plaintext = "One good key, one broken one.\n".toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot a key\n-----END PGP PUBLIC KEY BLOCK-----"),
            armoredSigningKey = null,
        )

        assertTrue(
            "an unusable recipient key must fail the send rather than silently drop that recipient",
            result is EncryptResult.Failed,
        )
    }

    /**
     * Every recipient key gets its own PKESK packet, and **both** recipients can open the message.
     *
     * Asserting only that the first key decrypts would pass on a message encrypted solely to that
     * key — and silently lock every CC'd recipient out in production.
     */
    @Test
    fun encryptsToEveryRecipientKey() {
        val plaintext = "Two recipients.\n"
        val result = PgpEncryptor.encrypt(
            plaintext = plaintext.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC, TestPgpSecondKey.ARMORED_PUBLIC),
            armoredSigningKey = null,
        )
        val armored = (result as EncryptResult.Ok).armored

        val factory = JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
        )
        val encryptedList = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPEncryptedDataList>()
            .first()
        assertEquals(
            "one public-key packet per recipient",
            2,
            encryptedList.encryptedDataObjects.asSequence().count(),
        )

        listOf(TestPgpPrivateKey.ARMORED_PRIVATE, TestPgpSecondKey.ARMORED_PRIVATE).forEach { key ->
            val decrypted = PgpDecryptor.decrypt(
                armoredPrivateKey = key,
                armoredMessage = armored,
                signerPublicKeys = emptyList(),
            )
            assertEquals(
                "every recipient must be able to open the message",
                plaintext,
                String((decrypted as DecryptResult.Ok).plaintext, Charsets.UTF_8),
            )
        }
    }

    /**
     * The Sent copy is encrypted to this key, and it must come from the unlocked private key rather
     * than from anything the server supplied — a hostile server handing back an attacker's "your"
     * public key would otherwise get a readable copy of every message sent, with nothing on screen
     * looking different.
     */
    @Test
    fun ownPublicKeyRoundTripsBackIntoAnEncryptionKey() {
        val own = PgpEncryptor.ownPublicKey(TestPgpPrivateKey.ARMORED_PRIVATE)

        val result = PgpEncryptor.encrypt(
            plaintext = "A copy for the Sent folder.\n".toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(requireNotNull(own)),
            armoredSigningKey = null,
        )

        val decrypted = PgpDecryptor.decrypt(
            armoredPrivateKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            armoredMessage = (result as EncryptResult.Ok).armored,
            signerPublicKeys = emptyList(),
        )
        assertEquals(
            "A copy for the Sent folder.\n",
            String((decrypted as DecryptResult.Ok).plaintext, Charsets.UTF_8),
        )
    }

    @Test
    fun refusesPlaintextOverTheCap() {
        val result = PgpEncryptor.encrypt(
            plaintext = ByteArray(MAX_DECRYPTED_PLAINTEXT_BYTES + 1),
            recipientPublicKeys = listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
            armoredSigningKey = null,
        )

        assertTrue("oversized plaintext must be refused", result is EncryptResult.Failed)
    }
}
