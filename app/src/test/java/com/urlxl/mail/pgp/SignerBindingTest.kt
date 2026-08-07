package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The two assertions that matter most are [autocryptKeyIsNeverConfirmed] and
 * [changedKeyIsNeverJustUnknown]. Both are cases where the wrong answer is *plausible* and quiet:
 * one over-claims identity on a key nobody checked, the other displays an active-attack signal as
 * the most routine message in the app.
 */
class SignerBindingTest {

    private fun sig(valid: Boolean = true) =
        RawSignature(present = true, valid = valid, signerKeyId = 1L)

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
}
