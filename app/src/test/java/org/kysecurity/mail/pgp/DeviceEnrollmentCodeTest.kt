package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the short authentication string the user reads off this device and types into the browser
 * during device enrollment.
 *
 * The browser derives the same code from the public key **the server handed it** and refuses to
 * seal the account's private key if the two disagree. That makes this derivation a bit-for-bit
 * contract between three independent implementations, and a disagreement does not fail loudly: it
 * fails as "the codes never match" on every honest enrollment, which the browser reports to the
 * user as *"the key this server gave the browser is not the key on that device"*. An encoding bug
 * here reaches the user as an active attack.
 *
 * See `docs/superpowers/plans/2026-08-05-device-enrollment-2c-handoff.md`.
 */
class DeviceEnrollmentCodeTest {

    /**
     * The normative vector, which until now had only ever been verified in the browser.
     * `frontend/src/lib/deviceEnrollment.test.ts` in kypost-server holds it as an inline snapshot
     * and is authoritative if it and the spec ever disagree — it runs on every frontend build.
     *
     * The key is a valid SEC1 encoding but deliberately **not** a point on P-256: the derivation
     * hashes bytes and must never need a curve operation, so this vector stays reproducible before
     * any ECDH is wired up.
     */
    @Test
    fun normativeVector_matchesTheBrowsersCode() {
        val rawKey = ByteArray(65)
        rawKey[0] = 0x04
        for (i in 1..32) rawKey[i] = 0x01
        for (i in 33..64) rawKey[i] = 0x02

        val code = deviceEnrollmentCode(rawPublicKey = rawKey, deviceId = "test-device", bucket = 14_000_000L)

        assertEquals("5R9K6FWA18A8YP", code)
    }

    /**
     * The code is 70 bits, not 50, and the length is load-bearing rather than cosmetic.
     *
     * With no commitment in the preimage the attacker's search is offline, so the only thing setting
     * its cost is the output width. At 50 bits a collision is ~2^50 SHA-256 compressions — about 14
     * GPU-hours and a few dollars per 120-second window — which is affordable for an adversary who
     * can write the relay's device table. A silent regression to a shorter code would not fail any
     * other test here, because the shorter code is a prefix of the longer one.
     */
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
