package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** See docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md for this contract. */
class DeviceEnrollmentCodeTest {

    /** Authoritative twin: `frontend/src/lib/deviceEnrollment.test.ts` in kypost-server. The key is
     *  a valid SEC1 encoding but deliberately not a point on P-256 — the derivation only hashes bytes. */
    @Test
    fun normativeVector_matchesTheBrowsersCode() {
        val rawKey = ByteArray(65)
        rawKey[0] = 0x04
        for (i in 1..32) rawKey[i] = 0x01
        for (i in 33..64) rawKey[i] = 0x02

        val code = deviceEnrollmentCode(rawPublicKey = rawKey, deviceId = "test-device", bucket = 14_000_000L)

        assertEquals("5R9K6FWA18A8YP", code)
    }

    /** 70 bits, not 50: the attacker's search is offline, so output width sets its whole cost. */
    @Test
    fun codeIsSeventyBitsWide() {
        val code = deviceEnrollmentCode(ByteArray(65).also { it[0] = 0x04 }, "any-device", 1L)

        assertEquals("14 Crockford characters at 5 bits each = 70 bits", 14, code.length)
    }

    /** Every character must come from the Crockford alphabet, which excludes I, L, O and U so the
     *  user cannot mistype the code by confusing them with 1 and 0. */
    @Test
    fun codeUsesOnlyTheCrockfordAlphabet() {
        val code = deviceEnrollmentCode(ByteArray(65).also { it[0] = 0x04 }, "any-device", 99L)

        assertTrue(code, code.all { it in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" })
    }
}
