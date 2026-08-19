package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream

/** JVM half of the pair with `PgpFingerprintSubkeyDeviceTest`: a JDK has EdDSA, Android does not. */
class PgpFingerprintSubkeyJvmTest {

    @Test
    fun computesFingerprintOfKeyWithEncryptionSubkey() {
        assertEquals(SUBKEY_FINGERPRINT, PgpFingerprint.compute(SUBKEY_ARMORED))
    }

    /** Grafting leaves the donor's binding signature in place over the wrong primary. */
    @Test
    fun graftedForeignSubkey_returnsNull() {
        val target = ringOf(SUBKEY_ARMORED)
        val donorSubkey = ringOf(DONOR_ARMORED).publicKeys.asSequence().first { !it.isMasterKey }

        val grafted = PGPPublicKeyRing.insertPublicKey(target, donorSubkey)

        assertNull(PgpFingerprint.compute(armor(grafted.encoded)))
    }

    /** Control for the graft: the same ring, re-armored without the donor subkey, still computes.
     *  Without this a failure above could just mean "the round trip broke the fixture". */
    @Test
    fun reArmoredWithoutGraft_stillComputes() {
        assertEquals(SUBKEY_FINGERPRINT, PgpFingerprint.compute(armor(ringOf(SUBKEY_ARMORED).encoded)))
    }

    private fun ringOf(armored: String): PGPPublicKeyRing =
        JcaPGPObjectFactory(PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)))
            .nextObject() as PGPPublicKeyRing

    private fun armor(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.UTF_8.name())
    }

    private companion object {
        /** ed25519 primary + cv25519 encryption subkey, `gpg --quick-generate-key` plus
         *  `--quick-add-key`, in a throwaway keyring. Kept byte-identical to the device test's
         *  fixture so the two platforms are compared on the same input. */
        const val SUBKEY_FINGERPRINT = "258E 286A 8DF6 5855 DF40 3110 9606 EA6B 6061 F145"

        val SUBKEY_ARMORED = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----

            mDMEan02TRYJKwYBBAHaRw8BAQdAZkjbBScLBLZ2rkaAX2X0Dq8cbOFVhg/VK5yc
            NUqbmvu0I1N1YmtleVByb2JlIDxwcm9iZUBleGFtcGxlLmludmFsaWQ+iJAEExYK
            ADgWIQQljihqjfZYVd9AMRCWBuprYGHxRQUCan02TQIbAQULCQgHAgYVCgkICwIE
            FgIDAQIeAQIXgAAKCRCWBuprYGHxRcDfAQDF3hc0O6nL3RYrnRiFgsRRkB6/7BRR
            TLKcCC+qJ9K47AEA5kE6FPCZaPLmun/i5bPNBPb1LQ0Z0On2nG1xaanXZgC4OARq
            fTZNEgorBgEEAZdVAQUBAQdAMQ8yZ+l4RODjmSjaMN+K9r3w1HSceqU9Bfw4MPxt
            ln4DAQgHiHgEGBYKACAWIQQljihqjfZYVd9AMRCWBuprYGHxRQUCan02TQIbDAAK
            CRCWBuprYGHxRUYmAQDPTnzFTUjsNvG5gRMu1oKcwllIWdsHpErEubmJLsG3NgD+
            LOTYXB06LrOKi5v3xX/RQOOyoWPdXd9zSJjI/MRDlAg=
            =oC88
            -----END PGP PUBLIC KEY BLOCK-----
        """.trimIndent()

        /** A second, unrelated key, purely to donate a subkey bound by the wrong primary. */
        val DONOR_ARMORED = """
            -----BEGIN PGP PUBLIC KEY BLOCK-----

            mDMEan03KRYJKwYBBAHaRw8BAQdAdidaz7gQ9HtRtfTjzmesMFbE7cjAklnHyRAk
            SkUuwS60IkdyYWZ0RG9ub3IgPGRvbm9yQGV4YW1wbGUuaW52YWxpZD6IkAQTFgoA
            OBYhBLHkTrZ9y0WQGpbQWZpW7XrbIi2wBQJqfTcpAhsBBQsJCAcCBhUKCQgLAgQW
            AgMBAh4BAheAAAoJEJpW7XrbIi2wAOkA/3JhoBouogJH+bB704NjzQUVPDRS02KI
            jrNTneXdxGBkAP42V8DbIDgML6yb7euj17RkrO2hjN7WkfYxSZC6vueBDLg4BGp9
            NykSCisGAQQBl1UBBQEBB0Au9Idxm/P9m00VWeRGdqCOAZ4rpuu/W9wc8sBt0Wdz
            bAMBCAeIeAQYFgoAIBYhBLHkTrZ9y0WQGpbQWZpW7XrbIi2wBQJqfTcpAhsMAAoJ
            EJpW7XrbIi2wLfYA/00r1up5mBK+vereezPOiOEUL6RI/pM5G6GELF1jRpXYAP4m
            Sz2ekZTHqTCvc3hzEyzfKRRRaAmo5rYlUy9pAB4WCA==
            =iJ/g
            -----END PGP PUBLIC KEY BLOCK-----
        """.trimIndent()
    }
}
