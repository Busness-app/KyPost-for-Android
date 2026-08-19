package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** [TEST_KEY_FINGERPRINT] is gpg's own reported fingerprint for [TEST_KEY] — an independent oracle. */
class PgpFingerprintTest {

    @Test
    fun compute_validArmoredKey_matchesFingerprintReportedByGpg() {
        val fingerprint = PgpFingerprint.compute(TEST_KEY)

        assertEquals(TEST_KEY_FINGERPRINT, fingerprint)
    }

    @Test
    fun compute_isDeterministic() {
        assertEquals(PgpFingerprint.compute(TEST_KEY), PgpFingerprint.compute(TEST_KEY))
    }

    /** Callers persist the whole blob; Bouncy Castle's ring constructor stops at a second key packet. */
    @Test
    fun compute_trailingSecondKeyRing_returnsNull() {
        // Has to be a packet-level append inside ONE armor block, which is what Bouncy Castle's
        // ring constructor silently ignores. Two separate armor blocks would not exercise it: the
        // decoder stream simply ends at the first block.
        assertNull(PgpFingerprint.compute(armor(ringBytes() + ringBytes())))
    }

    /** Control for the above: the same re-armoring round trip with a single ring must still work,
     *  so a failure of the previous test means "trailing data rejected", not "fixture broken". */
    @Test
    fun compute_reArmoredSingleRing_stillComputes() {
        assertEquals(TEST_KEY_FINGERPRINT, PgpFingerprint.compute(armor(ringBytes())))
    }

    private fun ringBytes(): ByteArray {
        val decoder = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
            TEST_KEY.byteInputStream(Charsets.UTF_8),
        )
        val ring = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(decoder).nextObject()
            as org.bouncycastle.openpgp.PGPPublicKeyRing
        return ring.encoded
    }

    private fun armor(bytes: ByteArray): String {
        val out = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.UTF_8.name())
    }

    /** A single ring must still be accepted — the trailing-data check must not reject the normal
     *  case, including with surrounding whitespace. */
    @Test
    fun compute_singleRingWithSurroundingWhitespace_stillComputes() {
        assertEquals(TEST_KEY_FINGERPRINT, PgpFingerprint.compute("\n\n" + TEST_KEY.trimEnd() + "\n\n"))
    }

    @Test
    fun compute_blank_returnsNull() {
        assertNull(PgpFingerprint.compute(""))
    }

    @Test
    fun compute_notPgpArmor_returnsNull() {
        assertNull(PgpFingerprint.compute("this is not a pgp key at all"))
    }

    @Test
    fun compute_headerWithNoKeyData_returnsNull() {
        // A server (or MITM) sending a corrupted/truncated key must be rejected, not silently
        // hashed into some other value that still renders as a plausible-looking fingerprint.
        val headerOnly = TEST_KEY.lineSequence().take(2).joinToString("\n")

        assertNull(PgpFingerprint.compute(headerOnly))
    }

    @Test
    fun compute_corruptedKeyBody_returnsNull() {
        val corrupted = TEST_KEY.replaceFirst(
            "mDMEalxKSBYJKwYBBAHaRw8BAQdAaLBvayt/AqeBFCxDOrvjb36gwol5tI+JU+6p",
            "mDMEalxKSBYJKwYBBAHaRw8BAQdAaLBvayt/AqeBFCxDOrvjb36gwol5tI+JU+6X",
        )

        assertNull(PgpFingerprint.compute(corrupted))
    }

    private companion object {
        const val TEST_KEY_FINGERPRINT = TestPgpKey.FINGERPRINT
        val TEST_KEY = TestPgpKey.ARMORED
    }
}
