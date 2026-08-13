package org.kysecurity.mail.security

import android.view.Window
import android.view.WindowManager
import org.kysecurity.mail.BuildConfig

/**
 * Single point at which `FLAG_SECURE` is applied, so the four windows that need it
 * ([LockedActivity], [UnlockActivity], [org.kysecurity.mail.push.MfaApprovalActivity] and every
 * dialog shown via [showSecurely]) cannot drift apart.
 *
 * The flag is skipped only when [BuildConfig.ALLOW_SCREENSHOTS] is set, which requires *both* a
 * debug variant and an explicit `-PallowScreenshots=true` on the Gradle invocation. It exists
 * because store and README screenshots have to be taken against a paired account, an emulator
 * cannot pair, and `FLAG_SECURE` is enforced below the app by SurfaceFlinger — so there is no
 * capture path on a real device without it. Release builds hardcode the field to false.
 */
fun Window.applySecureFlag() {
    if (BuildConfig.ALLOW_SCREENSHOTS) return
    setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
}
