package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [PgpFingerprint.compute] on a key that actually has an encryption subkey, on a real device.
 *
 * Every other fixture is a bare primary key with no subkey at all, so `hasValidBindingSignature` —
 * which runs a real signature verification through the platform JCA — was never once executed by a
 * test. Real accounts' keys all carry an encryption subkey, so on a real device that verification
 * sits on the path deciding whether the Security page can name the account's key at all.
 */
class PgpFingerprintSubkeyDeviceTest {

    @Test
    fun computesFingerprintOfKeyWithEncryptionSubkey() {
        assertEquals(
            PgpFingerprintSubkeyFixture.FINGERPRINT,
            PgpFingerprint.compute(PgpFingerprintSubkeyFixture.ARMORED),
        )
    }
}
