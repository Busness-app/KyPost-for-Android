package org.kysecurity.mail.pgp

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
        localKeys: Map<String, List<LocalSignerKey>> = emptyMap(),
    ) = EncryptedMessageReader(
        opener,
        payloads,
        localSignerKeys = { address -> localKeys[address].orEmpty() },
    ) to payloads

    private fun read(
        r: EncryptedMessageReader,
        unlockIfNeeded: Boolean = true,
        sender: String = "bob@example.com",
    ) = runBlocking { r.read("INBOX", "42", sender, unlockIfNeeded) }

    @Test
    fun aHeldKeyDecryptsWithoutPrompting() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
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
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.TooLarge, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aFetchFailureIsRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.Failed("offline")))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertTrue(read(r, unlockIfNeeded = false) is ReadOutcome.FetchFailed)
    }

    @Test
    fun aFailedDecryptDoesNotClearTheHeldKey() {
        // One bad payload says nothing about the key. Clearing would force a fresh biometric
        // prompt for every later message because of one broken message.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(encrypted = "not a pgp message")))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected DecryptFailed, got $outcome", outcome is ReadOutcome.DecryptFailed)
        assertEquals(TestPgpPrivateKey.ARMORED_PRIVATE, EnrollmentSession.peekForTest())
    }

    @Test
    fun theSignatureVerdictComesFromTheBoundKeyNotTheMessage() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aBoundKeyMakesAGenuineSignatureVerifyRatherThanAccusingTheSender() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            // NOT ARMORED_PRIVATE: a secret-key block is rejected where a PGPPublicKeyRing is expected.
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
        // Unrelated key material on purpose: ARMORED_PUBLIC would verify whatever .addresses claims.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
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
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            // "" per SignerKey's own KDoc: a conflicted entry carries no key material.
            publicKey = "",
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

    // The detached-signature branch: successPayload() always sets a non-blank encryptedPayload.

    @Test
    fun aDetachedSignatureFromAnUnboundKeyIsUnknownNotUnsigned() {
        // Relies on PGPPublicKeyRingCollection returning empty for empty input rather than throwing.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val (r, _) = reader(payloads = FakePayloadSource(detachedSignedPayload(signerKeys = emptyList())))

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, outcome.signature)
    }

    @Test
    fun aDetachedSignatureFromABoundKeyVerifies() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val bound = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = false,
            source = "autocrypt",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(bound))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, outcome.signature)
    }

    @Test
    fun aDetachedSignatureWithOnlyAConflictedKeyIsKeyChanged() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val conflicted = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = "",
            verified = false,
            source = "autocrypt",
            conflict = true,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(detachedSignedPayload(signerKeys = listOf(conflicted))),
        )

        val outcome = read(r, unlockIfNeeded = false) as ReadOutcome.Decrypted

        assertEquals(PgpSignatureState.KEY_CHANGED, outcome.signature)
    }

    @Test
    fun aClientUnprotectedAccountSaysSo() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.NotClientProtected))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.NotClientProtected, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aMessageWithNoOpenPgpPayloadIsTerminalNotRetryable() {
        val (r, _) = reader(payloads = FakePayloadSource(PgpPayloadResult.NoPayload))
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())

        assertEquals(ReadOutcome.NoEncryptedContent, read(r, unlockIfNeeded = false))
    }

    @Test
    fun aKeyThatVanishesBetweenUnsealAndFetchAsksForAnUnlockAgain() {
        // keyToHold = null: open() reports Opened without leaving a key, as a lock in the gap would.
        val opener = FakeVaultOpener(keyToHold = null)
        val (r, payloads) = reader(opener)

        val outcome = read(r, unlockIfNeeded = true)

        assertEquals(ReadOutcome.NeedsUnlock, outcome)
        assertEquals("the unseal itself must still have run exactly once", 1, opener.opened)
        assertEquals("must not spend a fetch when there is no key to decrypt with", 0, payloads.fetched)
    }

    @Test
    fun aRelaySuppliedVerifiedFlagCannotConfirmASigner() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val relayKey = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = true,
            source = "qr",
            conflict = false,
        )
        val (r, _) = reader(payloads = FakePayloadSource(successPayload(signerKeys = listOf(relayKey))))

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals(
            "a server-supplied verified flag must be capped at continuity, never identity",
            PgpSignatureState.VERIFIED_SEEN_BEFORE,
            (outcome as ReadOutcome.Decrypted).signature,
        )
    }

    @Test
    fun aLocallyHeldKeyIsResolvedForTheServersResolvedSender() {
        // The lookup key is `resolvedSender`. A relay that names a different sender gets a lookup
        // that misses, which is the fail-safe direction.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        var askedFor: String? = null
        val payloads = FakePayloadSource(successPayload(resolvedSender = "bob@example.com"))
        val r = EncryptedMessageReader(
            FakeVaultOpener(),
            payloads,
            localSignerKeys = { address -> askedFor = address; emptyList() },
        )

        read(r, unlockIfNeeded = false)

        assertEquals("bob@example.com", askedFor)
    }

    @Test
    fun aLocalKeyThatDidNotSignOutranksAnyRelayClaim() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val relayKey = SignerKey(
            addresses = listOf("bob@example.com"),
            publicKey = TestPgpPrivateKey.ARMORED_PUBLIC,
            verified = true,
            source = "qr",
            conflict = false,
        )
        val (r, _) = reader(
            payloads = FakePayloadSource(successPayload(signerKeys = listOf(relayKey))),
            // A real, parseable key that is NOT the one the message was signed with.
            localKeys = mapOf("bob@example.com" to listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true))),
        )

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
        assertEquals(
            PgpSignatureState.KEY_CHANGED,
            (outcome as ReadOutcome.Decrypted).signature,
        )
    }

    @Test
    fun aLookupFailureDegradesToTheRelayRatherThanFailingTheRead() {
        // Room can throw when a wipe closes the database out from under the lookup.
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val r = EncryptedMessageReader(
            FakeVaultOpener(),
            FakePayloadSource(successPayload()),
            localSignerKeys = { error("database is closed") },
        )

        val outcome = read(r, unlockIfNeeded = false)

        assertTrue("expected Decrypted, got $outcome", outcome is ReadOutcome.Decrypted)
    }
}
