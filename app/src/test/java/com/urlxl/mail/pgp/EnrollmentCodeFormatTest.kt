package com.urlxl.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The code is transcribed by a human across two devices, which is the failure the grouping exists
 * to prevent. Four groups of at most four is the pattern people already read off bank cards; two
 * groups of seven are long runs that are easy to lose your place in, and an omitted character in a
 * long run is silently wrong rather than visibly a wrong-length group.
 *
 * The browser's `formatEnrollmentCode` must group identically — see
 * `kypost-server/frontend/src/lib/deviceEnrollment.ts`. Grouping never reaches the hash:
 * `normalizeEnrollmentCode` strips `/[\s-]/g` before comparing.
 */
class EnrollmentCodeFormatTest {

    @Test
    fun groupsTheNormativeVectorAsFourThreeFourThree() {
        assertEquals("5R9K-6FW-A18A-8YP", formatEnrollmentCode("5R9K6FWA18A8YP"))
    }

    /**
     * The guard the browser's own suite already carries, for the same reason: a hardcoded slice
     * silently TRUNCATED the code when its width grew from 10 to 14 — and because the short code is
     * a prefix of the long one, the truncated form looked entirely plausible while dropping the four
     * characters carrying the extra 20 bits.
     */
    @Test
    fun neverDropsCharacters() {
        val rawKey = ByteArray(65).also {
            it[0] = 0x04
            for (i in 1..32) it[i] = 0x01
            for (i in 33..64) it[i] = 0x02
        }
        val code = deviceEnrollmentCode(rawKey, "test-device", 14_000_000L)

        assertEquals(code, formatEnrollmentCode(code).replace("-", ""))
    }

    /** A width this function was not designed around must still be shown in full, not clipped. */
    @Test
    fun aLongerCodeKeepsItsTail() {
        assertEquals("ABCD-EFG-HJKM-NPQ-RSTV", formatEnrollmentCode("ABCDEFGHJKMNPQRSTV"))
    }
}
