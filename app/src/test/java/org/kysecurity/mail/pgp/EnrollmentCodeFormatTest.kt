package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** The browser's `formatEnrollmentCode` must group identically; grouping never reaches the hash. */
class EnrollmentCodeFormatTest {

    @Test
    fun groupsTheNormativeVectorAsFourThreeFourThree() {
        assertEquals("5R9K-6FW-A18A-8YP", formatEnrollmentCode("5R9K6FWA18A8YP"))
    }

    /** The short code is a prefix of the long one, so a truncating slice looks entirely plausible. */
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
