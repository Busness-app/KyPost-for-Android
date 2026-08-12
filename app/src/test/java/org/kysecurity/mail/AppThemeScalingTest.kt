package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class AppThemeScalingTest {

    @Test
    fun scalePxByDensity_scalesByDensity() {
        assertEquals(20, scalePxByDensity(20, 1.0f))
        assertEquals(30, scalePxByDensity(20, 1.5f))
        assertEquals(60, scalePxByDensity(20, 3.0f))
    }

    @Test
    fun scalePxByDensity_truncatesFractionalPixels() {
        // 7 * 1.75 = 12.25 -> truncates to 12, matching the existing (value * density).toInt()
        // pattern used elsewhere in AppTheme.kt (e.g. dangerButtonBackground's stroke width).
        assertEquals(12, scalePxByDensity(7, 1.75f))
    }
}
