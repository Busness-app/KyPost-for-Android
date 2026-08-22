package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** A pin we cannot parse must be null, and null must fail the pairing rather than fall back to
 *  TOFU — otherwise a typo silently reopens the window this parameter exists to close. */
class SpkiPinNormalizationTest {

    private val valid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    @Test
    fun bareBase64_getsTheSha256Prefix() {
        assertEquals("sha256/$valid", normalizeSpkiPin(valid))
    }

    @Test
    fun alreadyPrefixed_isAcceptedUnchanged() {
        assertEquals("sha256/$valid", normalizeSpkiPin("sha256/$valid"))
    }

    @Test
    fun surroundingWhitespace_isTolerated() {
        assertEquals("sha256/$valid", normalizeSpkiPin("  $valid  "))
    }

    @Test
    fun wrongLength_isRejected() {
        assertNull(normalizeSpkiPin("AAAA="))
        assertNull(normalizeSpkiPin(valid.dropLast(1) + "AA="))
    }

    @Test
    fun nonBase64_isRejected() {
        assertNull(normalizeSpkiPin("not a pin"))
        assertNull(normalizeSpkiPin("sha1/$valid"))
        assertNull(normalizeSpkiPin("*".repeat(43) + "="))
    }

    @Test
    fun empty_isRejected() {
        assertNull(normalizeSpkiPin(""))
        assertNull(normalizeSpkiPin("sha256/"))
    }
}
