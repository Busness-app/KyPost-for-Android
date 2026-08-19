package org.kysecurity.mail.security

import android.app.Dialog

/** FLAG_SECURE is per-window: a Dialog needs its own, and the touch filter needs onShow. */
fun <T : Dialog> T.showSecurely(): T {
    window?.applySecureFlag()
    window?.applyOverlayProtection()
    setOnShowListener { window?.decorView?.filterObscuredTouchesRecursively() }
    show()
    return this
}
