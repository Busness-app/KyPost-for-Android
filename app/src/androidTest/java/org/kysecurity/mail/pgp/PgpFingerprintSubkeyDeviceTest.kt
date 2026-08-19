package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** The only fixture with an encryption subkey, so binding-signature verification runs. */
class PgpFingerprintSubkeyDeviceTest {

    @Test
    fun computesFingerprintOfKeyWithEncryptionSubkey() {
        assertEquals(
            PgpFingerprintSubkeyFixture.FINGERPRINT,
            PgpFingerprint.compute(PgpFingerprintSubkeyFixture.ARMORED),
        )
    }
}
