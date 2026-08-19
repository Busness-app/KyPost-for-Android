package org.kysecurity.mail.security

import android.view.View
import android.view.Window
import android.view.WindowManager
import org.kysecurity.mail.BuildConfig

/** Skipped only for BuildConfig.ALLOW_SCREENSHOTS: debug variant plus -PallowScreenshots. */
fun Window.applySecureFlag() {
    if (BuildConfig.ALLOW_SCREENSHOTS) return
    setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
}

/** FLAG_SECURE does not stop overlays; filterTouches covers what setHideOverlayWindows misses. */
fun Window.applyOverlayProtection() {
    setHideOverlayWindows(true)
    decorView.filterTouchesWhenObscured = true
}

/** The decorView flag misses Dialog content and views added after the window was created. */
fun View.filterObscuredTouchesRecursively() {
    filterTouchesWhenObscured = true
    if (this is android.view.ViewGroup) {
        for (i in 0 until childCount) getChildAt(i).filterObscuredTouchesRecursively()
    }
}
