package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class FontFaceCssTest {

    @Test
    fun buildMonoFontFaceCss_containsFontFaceRuleAndFamilyName() {
        val css = buildMonoFontFaceCss(byteArrayOf(1, 2, 3))

        assertTrue(css.contains("@font-face"))
        assertTrue(css.contains("font-family:'IBM Plex Mono'"))
        assertTrue(css.contains("data:font/ttf;base64,"))
    }

    @Test
    fun buildMonoFontFaceCss_roundTripsFontBytes() {
        val fontBytes = byteArrayOf(10, 20, 30, 40, 50, -1, 0, 127)

        val css = buildMonoFontFaceCss(fontBytes)
        val base64 = css.substringAfter("base64,").substringBefore(")")
        val decoded = Base64.getDecoder().decode(base64)

        assertEquals(fontBytes.toList(), decoded.toList())
    }
}
