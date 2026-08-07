package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
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
}
