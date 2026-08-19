package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Test
import org.kysecurity.mail.BuildConfig

/** `-PallowScreenshots=true` strips `FLAG_SECURE` app-wide; no shipped build may carry it. */
class ScreenshotFlagDefaultTest {

    @Test
    fun screenshotsAreBlockedUnlessExplicitlyRequested() {
        assertFalse(
            "Built with -PallowScreenshots=true: FLAG_SECURE is off app-wide.",
            BuildConfig.ALLOW_SCREENSHOTS,
        )
    }
}
