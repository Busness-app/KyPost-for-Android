package org.kysecurity.mail.security

import android.app.Dialog

/**
 * Shows [this] with `FLAG_SECURE` set and overlays suppressed, so it is excluded from screenshots
 * and screen recordings exactly as the Activity behind it is, and cannot have its buttons covered by
 * another app.
 *
 * **`FLAG_SECURE` is per-window and a Dialog creates its own.** Setting it on the Activity protects
 * the Activity's window and nothing else, so every PIN this app asks for through an `AlertDialog`
 * was capturable while the identical field inlined in [UnlockActivity] was not. The same applies to
 * [applyOverlayProtection], which is the half that matters for a prompt asking the user to approve
 * something: a consent dialog whose accept button can be covered is not a consent dialog.
 *
 * The touch filter is re-applied in `setOnShowListener` because the content view does not exist
 * until then.
 *
 * Works for both `android.app.AlertDialog` and `androidx.appcompat.app.AlertDialog`. Use it for
 * anything that renders a secret or asks for a decision; there is no cost to using it elsewhere.
 */
fun <T : Dialog> T.showSecurely(): T {
    window?.applySecureFlag()
    window?.applyOverlayProtection()
    setOnShowListener { window?.decorView?.filterObscuredTouchesRecursively() }
    show()
    return this
}
