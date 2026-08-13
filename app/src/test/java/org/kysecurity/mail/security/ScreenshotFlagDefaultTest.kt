package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Test
import org.kysecurity.mail.BuildConfig

/**
 * `-PallowScreenshots=true` strips `FLAG_SECURE` from every window in the app. It is meant to be
 * passed for one local build and never again, so this fails any build — CI included — that carries
 * it, rather than letting a screenshot build become the default one somebody ships from.
 */
class ScreenshotFlagDefaultTest {

    @Test
    fun screenshotsAreBlockedUnlessExplicitlyRequested() {
        assertFalse(
            "Built with -PallowScreenshots=true: FLAG_SECURE is off app-wide.",
            BuildConfig.ALLOW_SCREENSHOTS,
        )
    }
}
