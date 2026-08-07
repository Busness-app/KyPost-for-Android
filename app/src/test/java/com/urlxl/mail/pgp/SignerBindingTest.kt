package com.urlxl.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The three assertions that matter most are [autocryptKeyIsNeverConfirmed],
 * [changedKeyIsNeverJustUnknown], and [aSignatureFromAnotherContactsKeyIsNeverAttributedToThisSender].
 * All three are cases where the wrong answer is *plausible* and quiet: the first over-claims
 * identity on a key nobody checked, the second displays an active-attack signal as the most routine
 * message in the app, and the third lets any contact in the address book forge another contact's
 * `From` header and have their own signature attributed to the person they impersonated.
 */
class SignerBindingTest {

    // TestPgpKey.ARMORED's own key id, computed with the same parser [signatureStateFor] uses.
    // Deriving it rather than inventing a number keeps every fixture that claims "signed by this
    // key" honest against what the key material actually contains.
    private val testKeyId = signerKeyIdsOf(TestPgpKey.ARMORED).single()

    private fun sig(valid: Boolean = true, signerKeyId: Long = testKeyId) =
        RawSignature(present = true, valid = valid, signerKeyId = signerKeyId)

    private fun key(
        address: String = "bob@example.com",
        verified: Boolean = false,
        source: String = "autocrypt",
        conflict: Boolean = false,
        publicKey: String = TestPgpKey.ARMORED,
    ) = SignerKey(listOf(address), publicKey, verified, source, conflict)

    @Test
    fun unsignedIsNone() {
        val state = signatureStateFor(
            RawSignature(present = false, valid = false, signerKeyId = 0L),
            "bob@example.com",
            listOf(key()),
        )
        assertEquals(PgpSignatureState.NONE, state)
    }

    @Test
    fun confirmedKeyBoundToTheSenderIsConfirmed() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(verified = true, source = "qr")))
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun autocryptKeyIsNeverConfirmed() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(source = "autocrypt")))
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    @Test
    fun noKeyBoundToTheSenderIsUnknown() {
        val state = signatureStateFor(sig(), "carol@example.com", listOf(key(address = "bob@example.com")))
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun changedKeyIsNeverJustUnknown() {
        val state = signatureStateFor(sig(), "bob@example.com", listOf(key(conflict = true, publicKey = "")))
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aBadSignatureAgainstABoundKeyIsInvalid() {
        val state = signatureStateFor(sig(valid = false), "bob@example.com", listOf(key()))
        assertEquals(PgpSignatureState.INVALID, state)
    }

    @Test
    fun senderMatchingIgnoresDisplayNameAndCase() {
        // The relay sends the RAW From header. Comparing that against a bare address matched
        // nothing for any correspondent with a display name, while a bare `From: bob@…` — the
        // form an attacker always chooses — went on matching. A binding that only fires for the
        // attacker is worse than no binding.
        val state = signatureStateFor(
            sig(), "Bob Example <BOB@Example.com>", listOf(key(verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun aConflictOutranksAnOtherwiseGoodKeyForTheSameSender() {
        val state = signatureStateFor(
            sig(),
            "bob@example.com",
            listOf(key(verified = true, source = "manual"), key(conflict = true, publicKey = "")),
        )
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aSignatureFromAnotherContactsKeyIsNeverAttributedToThisSender() {
        // Eve is an ordinary contact in the address book — her key harvested like anyone else's.
        // She forges `From: bob@example.com` and signs with her OWN key. decrypt() resolves the
        // one-pass signature against the whole offered, non-conflicted key set and reports
        // valid = true — it verifies, just not against Bob's key. Attributing that to Bob because
        // *a* key is bound to Bob's address is exactly the bug this check exists to close.
        val notBobsKeyId = testKeyId + 1 // any id that is not TestPgpKey.ARMORED's own
        val state = signatureStateFor(
            sig(signerKeyId = notBobsKeyId),
            "bob@example.com",
            listOf(key(verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun aSignatureMatchingTheSendersBoundKeyIdIsStillVerified() {
        // The happy path must not regress: a signature genuinely made by the sender's own bound
        // key still verifies, both unconfirmed (VERIFIED_SEEN_BEFORE) and confirmed
        // (VERIFIED_CONFIRMED).
        val seenBefore = signatureStateFor(
            sig(signerKeyId = testKeyId), "bob@example.com", listOf(key(verified = false, source = "autocrypt")),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, seenBefore)

        val confirmed = signatureStateFor(
            sig(signerKeyId = testKeyId), "bob@example.com", listOf(key(verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, confirmed)
    }

    @Test
    fun anUnparseableBoundKeyGrantsNoPass() {
        // A bound key that will not parse must never be treated as a match just because *some*
        // key is bound to the sender — signerKeyIdsOf returns empty rather than throwing, and an
        // empty set can never contain signature.signerKeyId.
        val state = signatureStateFor(
            sig(signerKeyId = testKeyId),
            "bob@example.com",
            listOf(key(verified = true, source = "manual", publicKey = "this is not an OpenPGP key")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    // --- Finding 1: senderAddrSpec must bind the FIRST mailbox, matching the server, not the last. ---

    @Test
    fun senderAddrSpecBindsTheFirstNamedMailboxNotTheLast() {
        // The server's senderAddrSpec binds bob@example.com here. An earlier version of this
        // function took the LAST `<...>` in the header, which would bind eve@evil.com instead —
        // an ordinary contact (Eve) could then forge `From: Bob <bob@…>, Eve <eve@evil.com>`, sign
        // with her own harvested key, and have the badge read as bob@example.com's signer, while
        // the single-line inbox row (which ellipsizes the tail) shows the user "Bob".
        assertEquals(
            "bob@example.com",
            senderAddrSpec("Bob <bob@example.com>, Eve <eve@evil.com>"),
        )
    }

    @Test
    fun senderAddrSpecBindsTheFirstBareMailboxNotTheWholeString() {
        // Without angle brackets the old fallback returned the whole raw string (never matching
        // any stored address, silently going to SIGNER_UNKNOWN for a signature Bob actually made).
        // The server takes just the first bare address; this must too.
        assertEquals(
            "bob@example.com",
            senderAddrSpec("bob@example.com, eve@evil.com"),
        )
    }

    @Test
    fun eveCannotBorrowBobsIdentityByLeadingTheFromHeaderWithHisAddress() {
        // End-to-end version of the attack: Eve is a real contact with her OWN bound key at
        // eve@evil.com. She forges `From: Bob <bob@example.com>, Eve <eve@evil.com>` and signs
        // with her own key. senderAddrSpec must resolve the displayed sender to bob@example.com,
        // under which Eve's key is not bound at all, so the verdict is SIGNER_UNKNOWN — never a
        // verified badge borrowed from Bob's name.
        val eveKeyId = signerKeyIdsOf(TestPgpKey.ARMORED).single()
        val state = signatureStateFor(
            RawSignature(present = true, valid = true, signerKeyId = eveKeyId),
            "Bob <bob@example.com>, Eve <eve@evil.com>",
            listOf(key(address = "eve@evil.com", verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun anAngleAddrInsideAQuotedDisplayNameNeverBeatsTheRealMailbox() {
        // Regression: a bare `indexOf('<')` in addrSpecFromMailbox found the `<bob@x.com>` sitting
        // INSIDE the quoted, entirely attacker-controlled display name, and returned that instead
        // of the real mailbox `<eve@evil.com>`. Go's mail.ParseAddressList — what the server
        // actually runs — treats a quoted string as opaque and returns eve@evil.com, so this must
        // too: the '<' that starts the real angle-addr is the first one OUTSIDE quotes.
        assertEquals(
            "eve@evil.com",
            senderAddrSpec("\"Bob <bob@x.com>\" <eve@evil.com>"),
        )
    }

    // --- Finding 2: `verified` must come from the key that signed, not any key bound to the address. ---

    @Test
    fun verifiedIsReadFromTheKeyThatActuallySignedNotAnyBoundKey() {
        // Two keys can share an address whenever two contacts list it — contact address lists are
        // attacker-influenceable (pgp_qr_bind_confirm_body warns exactly this). Here bob@example.com
        // has TWO non-conflicted bound keys: one confirmed (manual) that did NOT sign this message,
        // and one Autocrypt-harvested key that DID. The verdict must reflect the key that actually
        // produced the signature, not "some bound key for this address is confirmed."
        val confirmedButDidNotSign =
            key(verified = true, source = "manual", publicKey = TestPgpPrivateKey.ARMORED_PUBLIC)
        val autocryptAndDidSign =
            key(verified = false, source = "autocrypt", publicKey = TestPgpKey.ARMORED)
        val state = signatureStateFor(
            sig(signerKeyId = testKeyId), // testKeyId belongs to TestPgpKey.ARMORED, not ARMORED_PUBLIC
            "bob@example.com",
            listOf(confirmedButDidNotSign, autocryptAndDidSign),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    // --- Finding 3: the subkey path, uncovered before this test. ---

    @Test
    fun aSignatureFromASubkeyIdIsAccepted() {
        // Real one-pass signatures are ordinarily made by a dedicated SUBKEY, never the primary
        // key. TestPgpKey.ARMORED (used everywhere else in this suite) has no subkey, so every
        // other test here is accidentally blind to this path. TestPgpPrivateKey.ARMORED_PUBLIC has
        // a primary key plus one subkey; this signs with the SUBKEY's id specifically.
        //
        // That subkey (204EA3568BC889DD, algo 18/ECDH) is ENCRYPTION-only per `gpg --list-packets`
        // (key flags 0C) — not a signing key. Naming this test "the signing subkey" would be false:
        // it actually pins that signerKeyIdsOf accepts a subkey's id regardless of usage flags,
        // exactly the looseness recorded in that function's KDoc. A signature could not really be
        // produced with this specific key in practice; the id match is what's under test.
        val subkeyId = subkeyIdOf(TestPgpPrivateKey.ARMORED_PUBLIC)
        assertNotEquals(primaryKeyIdOf(TestPgpPrivateKey.ARMORED_PUBLIC), subkeyId)
        val boundKey = key(verified = true, source = "manual", publicKey = TestPgpPrivateKey.ARMORED_PUBLIC)
        val state = signatureStateFor(sig(signerKeyId = subkeyId), "bob@example.com", listOf(boundKey))
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    // --- Finding 5: stored SignerKey.addresses entries are not guaranteed pre-normalized. ---

    @Test
    fun storedAddressIsNormalizedBeforeComparison() {
        // senderAddrSpec's output is always lowercase and trimmed, but every OTHER fixture in this
        // file cheats by supplying an already-normalized SignerKey.addresses entry too. This one
        // does not, so it actually exercises `it.trim().lowercase()` on the stored side of the
        // comparison rather than merely on the incoming header.
        val state = signatureStateFor(
            sig(),
            "bob@example.com",
            listOf(key(address = " Bob@Example.COM ", verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    private fun subkeyIdOf(armoredPublicKey: String): Long =
        publicKeysOf(armoredPublicKey).first { !it.isMasterKey }.keyID

    private fun primaryKeyIdOf(armoredPublicKey: String): Long =
        publicKeysOf(armoredPublicKey).first { it.isMasterKey }.keyID

    private fun publicKeysOf(armoredPublicKey: String) =
        PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.asSequence().flatMap { it.publicKeys.asSequence() }.toList()
}
