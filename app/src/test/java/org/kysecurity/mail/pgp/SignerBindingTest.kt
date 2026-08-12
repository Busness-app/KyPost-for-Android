package org.kysecurity.mail.pgp

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
            listOf(key()),
        )
        assertEquals(PgpSignatureState.NONE, state)
    }

    @Test
    fun confirmedKeyBoundToTheSenderIsConfirmed() {
        val state = signatureStateFor(sig(), listOf(key(verified = true, source = "qr")))
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun autocryptKeyIsNeverConfirmed() {
        val state = signatureStateFor(sig(), listOf(key(source = "autocrypt")))
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    @Test
    fun noKeysIsUnknown() {
        val state = signatureStateFor(sig(), emptyList())
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun changedKeyIsNeverJustUnknown() {
        val state = signatureStateFor(sig(), listOf(key(conflict = true, publicKey = "")))
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aBadSignatureAgainstABoundKeyIsInvalid() {
        val state = signatureStateFor(sig(valid = false), listOf(key()))
        assertEquals(PgpSignatureState.INVALID, state)
    }

    @Test
    fun aConflictOutranksAnOtherwiseGoodKeyForTheSameSender() {
        // A conflict outranks a good key for the same sender. Two entries for one address means
        // one of them is a key that changed, and reporting the survivor as verified would hide
        // precisely the event worth reporting.
        val state = signatureStateFor(
            sig(),
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
            sig(signerKeyId = testKeyId), listOf(key(verified = false, source = "autocrypt")),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, seenBefore)

        val confirmed = signatureStateFor(
            sig(signerKeyId = testKeyId), listOf(key(verified = true, source = "manual")),
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
            listOf(key(verified = true, source = "manual", publicKey = "this is not an OpenPGP key")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
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
        val state = signatureStateFor(sig(signerKeyId = subkeyId), listOf(boundKey))
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun theClientHoldsNoSenderParserOfItsOwn() {
        // signatureStateFor takes no sender argument at all — the property the deletion actually
        // established, and one noKeysIsUnknown cannot show (an empty signerKeys list can't prove
        // anything about a field that IS present). This pins the other half: SignerKey.addresses
        // is carried straight through from the server's binding and is never read here, even
        // though the field still exists on the data class and still holds attacker-influenceable
        // content. A key bound to a nonsense, unparseable "address" must verify exactly as if its
        // address were sane, because nothing in this function ever looks at it. If someone
        // reintroduces a From-header parser or an address comparison, either this fails to
        // compile (no sender to compare against) or this assertion starts failing (addresses
        // suddenly matter). See the KDoc on signatureStateFor for the 27-divergence harness that
        // made this a rule.
        val keyWithUselessAddress = key(
            address = "this is not even a valid address, and it must not matter",
            verified = true,
            source = "manual",
        )
        val state = signatureStateFor(sig(), listOf(keyWithUselessAddress))
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
