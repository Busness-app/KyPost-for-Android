package org.kysecurity.mail.security

import android.view.View
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

/**
 * Refuses to render, and refuses to accept touches, while another app is drawing over this window.
 *
 * `FLAG_SECURE` is not this control. It stops the window being *captured*; it does nothing about a
 * `TYPE_APPLICATION_OVERLAY` drawn on top of it, which is the opposite direction and the one that
 * matters for a consent prompt. Every window in this app that takes an irreversible decision — the
 * pairing confirmation reached from a `BROWSABLE` deep link, the MFA approve/deny tiles, every PIN
 * field — was a bare `View` with default touch handling, so a co-installed app holding
 * `SYSTEM_ALERT_WINDOW` could position its own button over the accept target and collect the tap.
 *
 * Two mechanisms, because they cover different halves:
 * - [Window.setHideOverlayWindows] (API 31, this app's `minSdk`) asks the system to hide other
 *   apps' overlays for as long as this window is showing. It is the real fix, and it is free.
 * - `filterTouchesWhenObscured` makes the view discard any touch delivered while something is
 *   drawn over it. It is the fallback for the overlay types `setHideOverlayWindows` does not
 *   cover (notably accessibility overlays), and it is what actually fails closed.
 */
fun Window.applyOverlayProtection() {
    setHideOverlayWindows(true)
    decorView.filterTouchesWhenObscured = true
}

/**
 * [View.setFilterTouchesWhenObscured] on this view and, recursively, everything under it.
 *
 * The window-level flag on `decorView` does not reach a `Dialog`'s content, nor views added to a
 * container after the window was created — [org.kysecurity.mail.push.MfaApprovalActivity] builds its
 * number-match tiles at runtime, which is exactly the tap an overlay wants.
 */
fun View.filterObscuredTouchesRecursively() {
    filterTouchesWhenObscured = true
    if (this is android.view.ViewGroup) {
        for (i in 0 until childCount) getChildAt(i).filterObscuredTouchesRecursively()
    }
}
