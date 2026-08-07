package com.urlxl.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** One test per exit-table row in the design spec. */
class EncryptedMessageReaderTest {

    @After fun cleanup() = EnrollmentSession.clear()

    private fun reader(
        opener: FakeVaultOpener = FakeVaultOpener(),
        payloads: FakePayloadSource = FakePayloadSource(successPayload()),
    ) = EncryptedMessageReader(opener, payloads) to payloads

    private fun read(
        r: EncryptedMessageReader,
        unlockIfNeeded: Boolean = true,
        sender: String = "bob@example.com",
    ) = runBlocking { r.read("INBOX", "42", sender, unlockIfNeeded) }

    @Test
    fun aHeldKeyDecryptsWithoutPrompting() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val opener = FakeVaultOpener()
        val (r, _) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals("must not prompt when the key is already held", 0, opener.opened)
    }

    @Test
    fun aColdSessionAsksForAnUnlockRatherThanPrompting() {
        val opener = FakeVaultOpener()
        val (r, payloads) = reader(opener)

        val outcome = read(r, unlockIfNeeded = false)

        assertEquals(ReadOutcome.NeedsUnlock, outcome)
        assertEquals("must not prompt on its own", 0, opener.opened)
        assertEquals("must not spend a fetch it cannot use", 0, payloads.fetched)
    }

    @Test
    fun anExplicitUnlockDecrypts() {
        val (r, _) = reader()

        val outcome = read(r, unlockIfNeeded = true)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
    }

    @Test
    fun aDismissedPromptIsCancelledNotAFailure() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Cancelled))

        assertEquals(ReadOutcome.Cancelled, read(r))
    }

    @Test
    fun anUnenrolledDeviceSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NotEnrolled))

        assertEquals(ReadOutcome.NotEnrolled, read(r))
    }

    @Test
    fun noSecureLockScreenSaysSo() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.NoSecureLockScreen))

        assertEquals(ReadOutcome.NoSecureLockScreen, read(r))
    }

    @Test
    fun anUnsealFailureIsDistinctFromACancel() {
        val (r, _) = reader(FakeVaultOpener(outcome = OpenOutcome.Failed("key invalidated")))

        assertTrue(read(r) is ReadOutcome.UnsealFailed)
    }

    @Test
    fun aTooLargeMessageSaysSoRatherThanBlamingTheNetwork() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.TooLarge))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)

        assertEquals(ReadOutcome.TooLarge, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aFetchFailureIsRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.Failed("offline")))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)

        assertTrue(read(r, unlockIfNeeded = false) is ReadOutcome.FetchFailed)
    }

    @Test
    fun aFailedDecryptDoesNotClearTheHeldKey() {
        // One bad payload says nothing about the key. Clearing would force a fresh biometric
        // prompt for every later message because of one broken message.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(encrypted = "not a pgp message")))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected DecryptFailed, got $outcome", outcome is ReadOutcome.DecryptFailed)
        assertEquals(TestPgpPrivateKey.ARMORED_PRIVATE, EnrollmentSession.peek())
    }

    @Test
    fun theSignatureVerdictComesFromTheBoundKeyNotTheMessage() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        // The message signs itself with a key we hold no binding for. That is SIGNER_UNKNOWN,
        // never VERIFIED_* — a message that vouches for itself proves only that whoever wrote
        // it owned a key.
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender() {
        // The regression this exists for: if the reader does not hand the bound keys to
        // PgpDecryptor, `valid` stays false, and signatureStateFor maps signed + bound + invalid
        // to INVALID — telling the user that every legitimately signed message from a
        // correspondent they DO hold a key for is an impersonation.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            // NOT ARMORED_PRIVATE: PGPPublicKeyRingCollection (what both PgpDecryptor's one-pass
            // verification and signerKeyIdsOf parse the offered key with) rejects a secret-key
            // block outright — "PGPSecretKeyRing found where PGPPublicKeyRing expected" — so an
            // armored private key can never stand in for a published public key here. ARMORED_PUBLIC
            // is the same key pair's public half, exported separately by gpg, exactly the shape a
            // real caller holds (see PgpDecryptorTest and TestPgpPrivateKey's own KDoc).
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = listOf(bound))))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
    }

    @Test
    fun aKeyBoundToADifferentSenderIsNeverOfferedToTheSignatureCheck() {
        // The forgery case, at the reader level. An ordinary contact signs a message and forges
        // the From header to name someone else. If the reader offered the whole address book, the
        // signature would verify against the forger's own key and be attributed to the person
        // named in From. Only keys the SERVER actually bound to the resolved sender may appear in
        // payload.signerKeys at all — the reader itself does no address matching (see
        // SignerBinding.signatureStateFor's KDoc and SignerBindingTest.theClientHoldsNoSenderParserOfItsOwn:
        // `.addresses` is carried straight through and never read past the server's own narrowing).
        // So the fixture that proves "never offered" has to use physically different key material
        // from the one that actually produced ARMORED_MESSAGE's signature — TestPgpKey.ARMORED,
        // a real, parseable, but unrelated key — rather than reusing ARMORED_PUBLIC, which IS the
        // signer's key regardless of which address a SignerKey entry claims it is bound to. Offering
        // it would spuriously verify no matter what `.addresses` says, which is exactly the false
        // positive this test exists to catch.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val otherContact = SignerKey(
            addresses = listOf("eve@evil.example"),
            publicKey = TestPgpKey.ARMORED,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(otherContact))),
        )

        val outcome = read(r, unlockIfNeeded = false, sender = "bob@example.com")
            as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aConflictedKeyYieldsKeyChanged() {
        // Named for what this actually proves, not for the offeredKeys filter in
        // EncryptedMessageReader: signatureStateFor returns KEY_CHANGED the moment ANY entry in
        // signerKeys has conflict = true, before it ever looks at which key was offered to
        // PgpDecryptor or whether the signature matched. That precedence means this test cannot
        // observe — and must not claim to prove — that the conflicted key's material was kept out
        // of the crypto layer. See the KDoc on the `offeredKeys` filter in
        // EncryptedMessageReader.kt for why the filter still stays despite being unobservable here.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE)
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PRIVATE,
            verified = false,
            source = "autocrypt",
            conflict = true,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(conflicted))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.KEY_CHANGED, outcome.signature)
    }
}
