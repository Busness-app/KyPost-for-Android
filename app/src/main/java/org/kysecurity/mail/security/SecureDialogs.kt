package org.kysecurity.mail.security

import android.app.Dialog
import android.view.WindowManager

/**
 * Shows [this] with `FLAG_SECURE` set, so it is excluded from screenshots, screen recordings and
 * non-secure displays exactly as the Activity behind it is.
 *
 * **`FLAG_SECURE` is a per-window flag and a Dialog creates its own window.** Setting it on the
 * Activity in [LockedActivity], [UnlockActivity] and
 * [org.kysecurity.mail.push.MfaApprovalActivity] therefore protects the Activity's window and nothing
 * else — every PIN this app asks for through an `AlertDialog` (set PIN, confirm PIN, change PIN,
 * disable lock, the credential-gate prompt, and the MFA fallback) was capturable by a screen
 * recorder or an overlay-capable app, while the identical field inlined in [UnlockActivity] was not.
 *
 * Applies to both `android.app.AlertDialog` and `androidx.appcompat.app.AlertDialog`, which share
 * [Dialog] as a supertype. Use it for anything that renders a secret; there is no cost to using it
 * for anything else.
 */
fun <T : Dialog> T.showSecurely(): T {
    window?.setFlags(
        WindowManager.LayoutParams.FLAG_SECURE,
        WindowManager.LayoutParams.FLAG_SECURE,
    )
    show()
    return this
}
